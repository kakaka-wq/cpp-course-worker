export default {
    async fetch(request, env) {
        const SUPABASE_URL = env.SUPABASE_URL;
        const SUPABASE_KEY = env.SUPABASE_KEY;
        const JWT_SECRET = env.JWT_SECRET;
        
        // 解析请求
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // 跨域配置
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        };

        // 处理 OPTIONS 请求
        if (method === "OPTIONS") {
            return new Response(null, { headers: corsHeaders });
        }

        // 生成 JWT
        async function generateJWT(payload) {
            const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
            const exp = Math.floor(Date.now() / 1000) + 86400; // 有效期1天
            const payloadStr = btoa(JSON.stringify({ ...payload, exp }));
            const signatureKey = await crypto.subtle.importKey(
                "raw",
                new TextEncoder().encode(JWT_SECRET),
                { name: "HMAC", hash: "SHA-256" },
                false,
                ["sign"]
            );
            const signature = await crypto.subtle.sign(
                "HMAC",
                signatureKey,
                new TextEncoder().encode(`${header}.${payloadStr}`)
            );
            return `${header}.${payloadStr}.${btoa(String.fromCharCode(...new Uint8Array(signature)))}`;
        }

        // 验证 JWT
        async function verifyJWT(token) {
            try {
                const [header, payloadStr, signature] = token.split(".");
                const payload = JSON.parse(atob(payloadStr));
                
                // 验证签名
                const signatureKey = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode(JWT_SECRET),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["verify"]
                );
                const valid = await crypto.subtle.verify(
                    "HMAC",
                    signatureKey,
                    new Uint8Array(atob(signature).split("").map(c => c.charCodeAt(0))),
                    new TextEncoder().encode(`${header}.${payloadStr}`)
                );
                
                // 验证过期时间
                if (!valid || payload.exp < Math.floor(Date.now() / 1000)) {
                    return null;
                }
                return payload;
            } catch (e) {
                return null;
            }
        }

        // Supabase 请求
        async function supabaseRequest(path, method, body = {}, headers = {}) {
            const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
                method,
                headers: {
                    "apikey": SUPABASE_KEY,
                    "Authorization": `Bearer ${SUPABASE_KEY}`,
                    "Content-Type": "application/json",
                    "Prefer": method === "POST" ? "return=representation" : "",
                    ...headers
                },
                body: method !== "GET" ? JSON.stringify(body) : undefined
            });
            return res.json();
        }

        // 1. 注册接口
        if (path === "/register" && method === "POST") {
            const { username, password } = await request.json();
            
            // 检查用户名是否已存在
            const existingUsers = await supabaseRequest(`/users?username=eq.${username}`, "GET");
            if (existingUsers.length > 0) {
                return new Response(JSON.stringify({ success: false, message: "用户名已存在" }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            // 加密密码
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const digest = await crypto.subtle.digest("SHA-256", data);
            const hashedPassword = Array.from(new Uint8Array(digest)).map(b => b.toString(16)).join("");
            
            // 创建用户
            const newUser = await supabaseRequest("/users", "POST", {
                username,
                password: hashedPassword
            });
            
            if (newUser.error) {
                return new Response(JSON.stringify({ success: false, message: "注册失败" }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            return new Response(JSON.stringify({ success: true }), {
                headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }

        // 2. 登录接口
        if (path === "/login" && method === "POST") {
            const { username, password } = await request.json();
            
            // 查找用户
            const users = await supabaseRequest(`/users?username=eq.${username}`, "GET");
            if (users.length === 0) {
                return new Response(JSON.stringify({ success: false, message: "用户名或密码错误" }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            const user = users[0];
            
            // 验证密码
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const digest = await crypto.subtle.digest("SHA-256", data);
            const hashedPassword = Array.from(new Uint8Array(digest)).map(b => b.toString(16)).join("");
            
            if (hashedPassword !== user.password) {
                return new Response(JSON.stringify({ success: false, message: "用户名或密码错误" }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            // 生成 JWT
            const token = await generateJWT({ user_id: user.id, username: user.username });
            
            return new Response(JSON.stringify({
                success: true,
                token,
                user: { id: user.id, username: user.username }
            }), {
                headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
        }

        // 3. 学习进度接口
        if (path === "/progress") {
            // 验证 JWT
            const authHeader = request.headers.get("Authorization");
            if (!authHeader || !authHeader.startsWith("Bearer ")) {
                return new Response(JSON.stringify({ success: false, message: "未登录" }), {
                    status: 401,
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            const token = authHeader.split(" ")[1];
            const payload = await verifyJWT(token);
            if (!payload) {
                return new Response(JSON.stringify({ success: false, message: "登录已过期" }), {
                    status: 401,
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            const user_id = payload.user_id;
            
            // 获取进度
            if (method === "GET") {
                const progress = await supabaseRequest(`/learning_progress?user_id=eq.${user_id}`, "GET");
                return new Response(JSON.stringify({
                    success: true,
                    data: progress.map(item => ({
                        course_url: item.course_url,
                        status: item.status,
                        last_opened_at: item.last_opened_at
                    }))
                }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
            
            // 更新进度
            if (method === "PUT") {
                const { courseUrl, status } = await request.json();
                
                // 检查是否已存在该课程的进度记录
                const existingProgress = await supabaseRequest(
                    `/learning_progress?user_id=eq.${user_id}&course_url=eq.${courseUrl}`,
                    "GET"
                );
                
                if (existingProgress.length > 0) {
                    // 更新
                    await supabaseRequest(
                        `/learning_progress?user_id=eq.${user_id}&course_url=eq.${courseUrl}`,
                        "PATCH",
                        { status, last_opened_at: new Date().toISOString() }
                    );
                } else {
                    // 创建
                    await supabaseRequest("/learning_progress", "POST", {
                        user_id,
                        course_url: courseUrl,
                        status,
                        last_opened_at: new Date().toISOString()
                    });
                }
                
                return new Response(JSON.stringify({ success: true }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" }
                });
            }
        }

        // 404
        return new Response(JSON.stringify({ success: false, message: "接口不存在" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    }
};
