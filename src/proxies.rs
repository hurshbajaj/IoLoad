use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::to_bytes;
use hyper::header::{HeaderName, HeaderValue, LOCATION};
use hyper::{Body, Request, Response, Uri};
use hyperlocal::Uri as local_uri;
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::structs::{client_type, Config, ErrorTypes, Server};
use crate::{timeline::*, CLIclient::{self}};
use crate::utils::*;

use deadpool_redis::Pool;
use deadpool_redis::redis::AsyncCommands;

pub async fn proxy(
    mut req: Request<Body>,
    client: client_type,
    origin_ip: String,
    timeout_dur: u64,
    redis_pool: Pool,
    _dos_threshhold: u64,
) -> Result<Response<Body>, anyhow::Error> {

    let (redis_cache, compression, js_challenge, challenge_url, method_hash_check, 
         check_in, check_out, min_ua_len, blocked_uas, ipc, max_concurrent) = {
        let cfg = CONFIG.read().await;
        (cfg.redis_cache, cfg.compression, cfg.js_challenge, cfg.challenge_url.clone(),
         cfg.Method_hash_check, cfg.Check_in, cfg.Check_out, cfg.min_ua_len,
         cfg.blocked_uas.clone(), cfg.ipc, cfg.max_concurrent_reqs_ps)
    };

    CLIclient::total.fetch_add(1, Ordering::SeqCst);

    dos(origin_ip.clone());

    if ban_list.read().await.contains(&origin_ip.clone()){
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::DDoSsus)))
    }

    let mut check_o = false;
    
    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let Hmac = req.headers()
        .get("X-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let methd = req.method();

    if user_agent.len() < min_ua_len as usize || blocked_uas.contains(&(user_agent.to_string())) {
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::InvalidUserAgent)));
    }

    {
        if req.uri().path() == challenge_url && js_challenge{
            match serve_js_challenge("/").await {
                Ok(x) => return Ok(x),
                Err(_) => return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Load_balance_Verification_Fail)))
            }
        }

        if method_hash_check{
            if check_in {
                if !verify_hmac_from_env(methd.to_string().as_str(), Hmac) {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Suspiscious)));
                }
            }
            if check_out {
                check_o = true;
            }
        }
        if !has_js_challenge_cookie(&req) && js_challenge{
            let redirect_url = format!("{}", challenge_url);
            return Ok(Response::builder()
                .status(302)
                .header(LOCATION, redirect_url)
                .body(Body::empty())
                .unwrap());
        }
    }

    let mut count = 0;
    let mut X = CLIclient::reqs.write().await;
    *X += 1u64;
    drop(X);
    
    //cache <<
    let mut cache_req: Request<Body>;
    (cache_req, req) = clone_request(req).await.unwrap();
    let cache_key = build_cache_key(cache_req, compression).await.unwrap();

    if redis_cache {
        {
            let mut conn = redis_pool.get().await?;
            match conn.get::<_, Option<Vec<u8>>>(&cache_key).await {
                Ok(Some(mut cached_value)) => {
                    if compression {
                        let decompressed = decompress_bytes(&mut cached_value)?;
                        return Ok(Response::new(Body::from(decompressed)))
                    }else{
                        return Ok(Response::new(Body::from(cached_value)))
                    }
                }
                _ => {}
            }
        }
    }

    const MAX_RETRIES: i32 = 3;
    let mut active_target = 0;

    loop {
        if count >= MAX_RETRIES {
            if active_target > 0 { CLIclient::total_bad.fetch_add(1, Ordering::SeqCst); }
            return Err(anyhow::Error::msg(format_error_type(ErrorTypes::NoHealthyServerFound)));
        }

        let req_clone: Request<Body>;
        (req_clone, req) = clone_request(req).await.unwrap();

        let config_snapshot = CONFIG.read().await.clone();
        
        let updated_res = updateTARGET(config_snapshot.clone()).await;
        if  updated_res != ErrorTypes::Nil{
            if updated_res == ErrorTypes::GracefulShutdownUnderway{
                return Err(anyhow::Error::msg(format_error_type(ErrorTypes::GracefulShutdownUnderway)));
            }
            count += 1;
            continue; 
        }
        active_target += 1;

        let target_gg = {
            let target_sgg = TARGET.read().await;
            match target_sgg.clone() {
                Some(t) => t,
                None => {
                    count += 1;
                    continue; 
                }
            }
        };

        let target = target_gg.read().await;

        // Check concurrent limit
        if target.concurrent.load(Ordering::SeqCst) >= max_concurrent {
            count += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }

        let mut proxied_req = Request::builder();

        if ipc {
            let urii: hyper::Uri = local_uri::new(target.ip.clone(), req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")).into();
            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(urii)
                .version(req_clone.version());
        } else {
            let new_uri = format!(
                "{}{}",
                target.ip,
                req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
            )
                .parse::<Uri>()
                .expect("Failed to parse URI");

            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(new_uri)
                .version(req_clone.version());
        }

        for (key, value) in req_clone.headers() {
            proxied_req = proxied_req.header(key, value);
        }

        proxied_req = proxied_req.header("X-Forwarded-For", origin_ip.clone());
        if check_o {
            let holdd = methd_hash_from_env(req_clone.method().as_str());
            proxied_req = proxied_req.header("X-secret", holdd.as_str());
        }

        let proxied_req = proxied_req
            .body(req_clone.into_body())
            .expect("Failed to build request");

        let start = Instant::now();

        target.concurrent.fetch_add(1, Ordering::SeqCst);

        let timeout_result = match client {
            client_type::Http(ref x) => timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await,
            client_type::Ipc(ref x) => timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await,
        };

        target.concurrent.fetch_sub(1, Ordering::SeqCst);
        drop(target); 
        let target_arc = {
            let target_guard = TARGET.read().await;
            match target_guard.clone() {
                Some(t) => t,
                None => {
                    count += 1;
                    continue;
                }
            }
        };

        let mut target_mut = target_arc.write().await;

        match timeout_result {
            Ok(result) => match result {
                Ok(mut response) => {
                    // for metrics + weight
                    let mut max = max_res.write().await;
                    if start.elapsed().as_millis() as u64 > *max as u64 {
                        *max = start.elapsed().as_millis() as u64;
                    }
                    if start.elapsed().as_millis() as u64 > max_res_n.load(Ordering::SeqCst){
                        max_res_n.store(start.elapsed().as_millis() as u64, Ordering::SeqCst);
                    }
                    target_mut.res_time = ((start.elapsed().as_millis() as u64) + target_mut.res_time) / 2 as u64;

                    // >> cache
                    if redis_cache {
                        if let Some(cache_control) = response.headers().get("cache-control") {
                            if let Ok(cc_str) = cache_control.to_str() {
                                if let Ok(max_age_secs) = cc_str.parse::<usize>() {
                                    if max_age_secs > 0 {
                                        let status = response.status();
                                        let version = response.version();
                                        let headers = response.headers().clone();

                                        let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                                        let body_string = String::from_utf8(body_bytes.to_vec())?;

                                        let compressed = compress_str(&body_string)?;

                                        let mut conn = redis_pool.get().await?;
                                        if compression {
                                            let _ = conn.set_ex::<_, _, ()>(&cache_key, compressed, max_age_secs as u64).await;
                                        } else {
                                            let _ = conn.set_ex::<_, _, ()>(&cache_key, body_string.clone(), max_age_secs as u64).await;
                                        }

                                        let mut new_response = Response::builder()
                                            .status(status)
                                            .version(version);

                                        for (k, v) in headers.iter() {
                                            new_response = new_response.header(k, v);
                                        }

                                        let rebuilt = new_response
                                            .body(Body::from(body_string))
                                            .unwrap();

                                        return Ok(rebuilt);
                                    }
                                }
                            }
                        }
                    }

                    return Ok(response)
                }
                Err(_) => {
                    count += 1;
                    if count >= MAX_RETRIES {
                        CLIclient::total_bad.fetch_add(1, Ordering::SeqCst);
                        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::BadRequest)))
                    }
                    // Retry with next server :D
                }
            },
            Err(_) => {
                if target_mut.strict_timeout {
                    target_mut.is_active = false;
                } else {
                    target_mut.timeout_tick += 1;
                    if target_mut.timeout_tick >= 3 {
                        target_mut.is_active = false;
                    }
                }
                count += 1;
                if count >= MAX_RETRIES {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
                }
                // Retry with next server ((:
            }
        }
    }
}

pub async fn health_check_proxy(
    client: client_type,
    timeout_dur: u64,
    server: Arc<RwLock<Server>>,
    health_check_path: String
) -> Result<Response<Body>, anyhow::Error> {

    let (server_ip, ipc) = {
        let target = server.read().await;
        (target.ip.clone(), CONFIG.read().await.ipc.clone())
    };

    let mut req = Request::builder().body(Body::empty()).unwrap();

    if ipc {
        let urii: hyper::Uri = local_uri::new(server_ip.clone(), health_check_path.as_str()).into();
        req = Request::builder()
            .method("GET")
            .uri(urii)
            .body(Body::empty())
            .unwrap();
    } else {
        let new_uri = format!("{}{}", server_ip, health_check_path)
            .parse::<Uri>()
            .expect("Failed to parse URI");

        req = Request::builder()
            .method("GET")
            .uri(new_uri)
            .body(Body::empty())
            .unwrap();
    }

    let timeout_result = match client {
        client_type::Http(ref x) => timeout(Duration::from_secs(timeout_dur), x.request(req)).await,
        client_type::Ipc(ref x) => timeout(Duration::from_secs(timeout_dur), x.request(req)).await,
    };

    let mut target_mut = server.write().await;

    match timeout_result {
        Ok(result) => match result {
            Ok(response) => {
                target_mut.is_active = true;
                target_mut.timeout_tick = 0;                 
                let max_res_val = *max_res.read().await;
                if max_res_val != 0 {
                    target_mut.weight = ((1.0 - (target_mut.res_time as f64 / max_res_val as f64)) * 10.0).max(1.0) as u64;
                }
                Ok(response)
            }
            Err(_) => {
                target_mut.is_active = false;
                Err(anyhow::Error::msg(format_error_type(ErrorTypes::HealthCheckFailed)))
            }
        },
        Err(_) => {
            target_mut.is_active = false;
            Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
        }
    }
}

fn dos(ip: String){
    let entry = RATE_LIMITS.entry(ip.clone()).or_insert_with(|| AtomicU32::new(0));
    entry.fetch_add(1, Ordering::SeqCst);
}

async fn clone_request(req: Request<Body>) -> Result<(Request<Body>, Request<Body>), hyper::Error> {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body).await.unwrap();

    let mut req1 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    let mut req2 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    for (key, value) in parts.headers.clone() {
        if let Some(k) = key {
            let header_name = HeaderName::from_str(k.as_str()).unwrap();
            let header_value = HeaderValue::from_str(value.to_str().unwrap()).unwrap();
            req1.headers_mut().insert(header_name.clone(), header_value.clone());
            req2.headers_mut().insert(header_name, header_value);
        }
    }

    Ok((req1, req2))
} 

async fn updateTARGET(config: Config) -> ErrorTypes {
    if *proc_shutdown.read().await {
        return ErrorTypes::GracefulShutdownUnderway;
    }
    
    if config.servers.is_empty() {
        return ErrorTypes::NoHealthyServerFound;
    }

    let mut at_idx = atServerIdx.write().await;

    if at_idx[1] >= config.servers[at_idx[0] as usize].read().await.weight {
        at_idx[1] = 0;
        at_idx[0] = (at_idx[0] + 1) % config.servers.len() as u64;
    } else {
        at_idx[1] += 1;
    }

    let mut found_healthy = false;
    let mut checked = 0;
    let mut current_idx = at_idx[0];

    while !found_healthy && checked < config.servers.len() {
        let server = config.servers[current_idx as usize].clone();
        {
            let server_guard = server.read().await;
            if server_guard.is_active {
                found_healthy = true;
            }
        }

        if found_healthy {
            *TARGET.write().await = Some(server);
            *at_idx = [current_idx, 0];
            return ErrorTypes::Nil;
        }

        current_idx = (current_idx + 1) % config.servers.len() as u64;
        checked += 1;
    }

    return ErrorTypes::NoHealthyServerFound;
}
