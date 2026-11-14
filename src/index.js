
const CJIT_SESSION_COOKIE='__Host-cjit_iam_session';
function cjitReadCookie(req,name){const a=(req.headers.get('cookie')||'').split(';').map(s=>s.trim()).find(v=>v.startsWith(name+'='));return a?a.slice(name.length+1):''}
function cjitRndB64(){return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function cjitAjaxError(message,status=401){return new Response(JSON.stringify({ok:false,error:message}),{status,headers:{'content-type':'application/json','cache-control':'no-store'}})}
function cjitRedirect(location,cookies=[]){const h=new Headers({Location:location,'cache-control':'no-store'});for(const cookie of cookies)h.append('set-cookie',cookie);return new Response(null,{status:302,headers:h})}
async function cjitIAMMiddleware(req,env,app,adminRequired=false){
 const u=new URL(req.url),path=u.pathname;
 if(!env.IAM||typeof env.IAM.fetch!=='function')return cjitAjaxError('CJIT IAM currently unavailable',503);
 if(path==='/auth/cjit-iam/callback'){
   if(req.method!=='GET')return cjitAjaxError('Invalid method',405);
   const state=cjitReadCookie(req,'__Host-cjit_iam_state'),verifier=cjitReadCookie(req,'__Host-cjit_iam_verifier'),code=u.searchParams.get('code')||'';
   if(!/^[A-Za-z0-9_-]{43}$/.test(state)||!/^[-_A-Za-z0-9]{43}$/.test(verifier)||u.searchParams.get('state')!==state||!/^[0-9a-f]{64}$/.test(code))return cjitAjaxError('Invalid login callback',400);
   let response;try{response=await env.IAM.fetch('https://iam.cjitnetworks.com/sso/exchange',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({app,redirect_uri:u.origin+'/auth/cjit-iam/callback',code,code_verifier:verifier})})}catch{return cjitAjaxError('CJIT IAM unavailable',503)}
   if(!response.ok)return cjitAjaxError('Access denied',403);
   const data=await response.json();if((adminRequired&&data.role!=='admin')||!data.authorized||!/^[0-9a-f]{64}$/.test(data.token||''))return cjitAjaxError('Access denied',403);
   return cjitRedirect('/',[CJIT_SESSION_COOKIE+'='+data.token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=21600','__Host-cjit_iam_state=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0','__Host-cjit_iam_verifier=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0']);
 }
 if(path==='/auth/cjit-iam/logout'){
   if(req.method!=='POST'||req.headers.get('origin')!==u.origin)return cjitAjaxError('Invalid sign-out request',403);
   const token=cjitReadCookie(req,CJIT_SESSION_COOKIE);
   if(/^[0-9a-f]{64}$/.test(token))try{await env.IAM.fetch('https://iam.cjitnetworks.com/sso/revoke',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({app,token})})}catch{}
   return cjitRedirect('/',[CJIT_SESSION_COOKIE+'=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0']);
 }
 if(path==='/auth/cjit-iam/health'&&req.method==='GET'){
   try {const r=await env.IAM.fetch('https://iam.cjitnetworks.com/sso/health');return new Response(JSON.stringify({ok:r.ok}),{status:r.ok?200:503,headers:{'content-type':'application/json','cache-control':'no-store'}})}catch{return cjitAjaxError('Identity service unreachable',503)}
 }
 if(!['GET','HEAD','OPTIONS'].includes(req.method)&&((req.headers.get('origin')&&req.headers.get('origin')!==u.origin)||req.headers.get('sec-fetch-site')==='cross-site'))return cjitAjaxError('Cross-origin request denied',403);
 const token=cjitReadCookie(req,CJIT_SESSION_COOKIE);
 if(/^[0-9a-f]{64}$/.test(token)){try{const r=await env.IAM.fetch('https://iam.cjitnetworks.com/sso/introspect',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({app,token})});if(r.ok){const claim=await r.json();if(claim.authorized===true&&(!adminRequired||claim.role==='admin')&&Array.isArray(claim.permissions)&&claim.permissions.includes('app.use'))return true;}}catch{}}
 if(req.method!=='GET'||!(req.headers.get('accept')||'').includes('text/html'))return cjitAjaxError('CJIT IAM sign-in required');
 const state=cjitRndB64(),verifier=cjitRndB64(),digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier)),challenge=btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const auth=new URL('https://iam.cjitnetworks.com/sso/authorize');auth.searchParams.set('app',app);auth.searchParams.set('redirect_uri',u.origin+'/auth/cjit-iam/callback');auth.searchParams.set('state',state);auth.searchParams.set('code_challenge',challenge);auth.searchParams.set('code_challenge_method','S256');
 return cjitRedirect(auth.toString(),['__Host-cjit_iam_state='+state+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=180','__Host-cjit_iam_verifier='+verifier+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=180']);
}



const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const BACKEND_TIMEOUT_MS = 15_000;

function secureResponse(response) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Strict-Transport-Security", "max-age=31536000");
  headers.set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'");
  const vary = headers.get("Vary");
  if (!vary || !vary.split(",").some((value) => value.trim().toLowerCase() === "authorization")) {
    headers.set("Vary", vary ? `${vary}, Authorization` : "Authorization");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function errorResponse(message, status, extraHeaders = {}) {
  return secureResponse(new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders }
  }));
}

function unauthorized() {
  return secureResponse(new Response("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="CJIT Staff"' }
  }));
}

async function isAuth(req, env) {
  if (typeof env.ADMIN_PASSWORD !== "string" || !env.ADMIN_PASSWORD) return false;
  const authorization = req.headers.get("Authorization") || "";
  if (authorization.length > 4096) return false;
  const match = authorization.match(/^Basic\s+([^\s]+)\s*$/i);
  if (!match) return false;
  try {
    const credentials = atob(match[1]);
    if (credentials.indexOf(":") < 1) return false;
    const encoder = new TextEncoder();
    const [provided, expected] = await Promise.all([
      crypto.subtle.digest("SHA-256", encoder.encode(credentials)),
      crypto.subtle.digest("SHA-256", encoder.encode(`${env.ADMIN_USER || "cjit"}:${env.ADMIN_PASSWORD}`))
    ]);
    const left = new Uint8Array(provided);
    const right = new Uint8Array(expected);
    let difference = 0;
    for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
    return difference === 0;
  } catch {
    return false;
  }
}

function isCrossOriginMutation(req, url) {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return false;
  const origin = req.headers.get("Origin");
  const site = req.headers.get("Sec-Fetch-Site");
  return (origin !== null && origin !== url.origin) || site === "cross-site" || (site === "same-site" && origin !== url.origin);
}

async function fetchBackend(binding, request) {
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error("Backend request timed out");
      error.name = "TimeoutError";
      reject(error);
      controller.abort();
    }, BACKEND_TIMEOUT_MS);
  });
  try {
    return await Promise.race([
      binding.fetch(new Request(request, { signal: controller.signal })),
      deadline
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export default {
  async fetch(req, env) {
    const iamGate=await cjitIAMMiddleware(req,env,'cjit-buildos');if(iamGate!==true)return iamGate;
    const url = new URL(req.url);
    if (isCrossOriginMutation(req, url)) return errorResponse("Cross-origin request denied", 403);
    try {
      if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
        if (!env.API_TOKEN || typeof env.BUILDCORE?.fetch !== "function") {
          console.error("BuildOS API binding is not configured");
          return errorResponse("Service unavailable", 503);
        }
        const normalizedPath = url.pathname === "/api" ? "/api/v1" : (url.pathname === "/api/v1" || url.pathname.startsWith("/api/v1/")) ? url.pathname : url.pathname.replace(/^\/api(?=\/|$)/, "/api/v1");
        const target = "https://buildcore.internal" + normalizedPath + url.search;
        const headers = new Headers(req.headers);
        for (const name of ["Host", "Cookie", "CF-Access-Jwt-Assertion", "CF-Access-Client-Id", "CF-Access-Client-Secret", "CF-Access-Authenticated-User-Email"]) {
          headers.delete(name);
        }
        headers.set("Authorization", `Bearer ${env.API_TOKEN}`);
        const init = { method: req.method, headers, redirect: "manual" };
        if (req.method !== "GET" && req.method !== "HEAD" && req.body !== null) {
          init.body = req.body;
          init.duplex = "half";
        }
        return secureResponse(await fetchBackend(env.BUILDCORE, new Request(target, init)));
      }
      if (typeof env.ASSETS?.fetch !== "function") {
        console.error("BuildOS asset binding is not configured");
        return errorResponse("Service unavailable", 503);
      }
      const assetHeaders = new Headers(req.headers);
      assetHeaders.delete("Authorization");
      assetHeaders.delete("Cookie");
      return secureResponse(await env.ASSETS.fetch(new Request(req, { headers: assetHeaders })));
    } catch (error) {
      if (error?.name === "TimeoutError") {
        console.error("BuildOS backend request timed out");
        return errorResponse("Backend request timed out", 504);
      }
      console.error("BuildOS upstream request failed");
      return errorResponse("Service temporarily unavailable", 502);
    }
  }
};
