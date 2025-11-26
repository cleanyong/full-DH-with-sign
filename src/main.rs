mod crypto;

use std::{
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use crypto::{
    compute_shared_secret, derive_aes256_key, encode_b64, generate_dh_keypair,
    handshake_message_from_parts, parse_handshake_message, sign_ephemeral,
    verify_ephemeral_signature, DhKeyPair, HandshakeMessage,
    generate_and_save_signing_key_pair_with_prefix, LongTermSigning,
    load_longterm_signing,
};
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    role: String,
    dh_keys: Arc<Mutex<Option<DhKeyPair>>>,
    last_offer: Arc<Mutex<Option<HandshakeMessage>>>,
    longterm_signing: LongTermSigning,
}

#[tokio::main]
async fn main() {
    let mut args = env::args();
    let _program = args.next();
    let arg_role = args.next().unwrap_or_else(|| "alice".to_string());
    let (role, port) = match arg_role.to_lowercase().as_str() {
        "alice" => ("alice".to_string(), 3000u16),
        "bob" => ("bob".to_string(), 3001u16),
        other => {
            eprintln!("未知角色 `{other}`，請使用 `alice` 或 `bob` 作為參數，例如：");
            eprintln!("  cargo run -- alice");
            eprintln!("  cargo run -- bob");
            std::process::exit(1);
        }
    };

    let prefix = if role == "alice" { "alice" } else { "bob" };
    let longterm_signing = match load_longterm_signing(prefix) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("載入 {role} 的 Ed25519 簽名金鑰失敗（可能尚未建立金鑰檔）：{e}");
            eprintln!("將自動為 {role} 產生新的簽名金鑰檔案...");
            if let Err(gen_err) = generate_and_save_signing_key_pair_with_prefix(prefix) {
                eprintln!("自動產生簽名金鑰失敗: {gen_err}");
                std::process::exit(1);
            }
            load_longterm_signing(prefix).expect("自動產生後載入簽名金鑰失敗")
        }
    };

    let state = AppState {
        role: role.clone(),
        dh_keys: Arc::new(Mutex::new(None)),
        last_offer: Arc::new(Mutex::new(None)),
        longterm_signing,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/generate", post(generate_offer))
        .route("/download-offer.json", get(download_offer))
        .route("/process", post(process_response))
        .with_state(state);

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    println!(
        "Running {role} server on http://{addr}  (使用方式：cargo run -- alice / cargo run -- bob)"
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let title = if state.role == "alice" {
        "Alice Diffie-Hellman Handshake"
    } else {
        "Bob Diffie-Hellman Handshake"
    };

    let role_label = if state.role == "alice" {
        "Alice"
    } else {
        "Bob"
    };
    let peer_label = if state.role == "alice" { "Bob" } else { "Alice" };

    let pk_b64 = &state.longterm_signing.pk_b64;
    let sk_preview = mask_secret_preview(&state.longterm_signing.sk_b64);

    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; }}
    textarea {{ width: 100%; height: 200px; }}
    pre {{ background: #f5f5f5; padding: 1rem; overflow-x: auto; }}
    button {{ padding: 0.5rem 1rem; margin-top: 0.5rem; }}
  </style>
</head>
<body>
  <h1>{title}</h1>

  <p><strong>你現在這一端是：{role_label}</strong></p>
  <section>
    <h2>Step 0: 本端長期簽名金鑰 (Ed25519)</h2>
    <p>
      啟動時，程式會嘗試從本地檔案載入本端（{role_label}）的簽名金鑰；
      如果檔案不存在，會自動在本機產生新的簽名金鑰並存檔，然後載入。
    </p>
    <p><strong>簽名公鑰 (Base64, 完整顯示)：</strong></p>
    <pre>{pk_b64}</pre>
    <p><strong>簽名私鑰 (Base64, 只顯示頭尾，中間以星號遮蔽)：</strong></p>
    <pre>{sk_preview}</pre>
  </section>
  <p>
    建議：開兩個 terminal 視窗，分別執行
  </p>
  <pre>
cargo run -- alice    # 會在 127.0.0.1:3000 上開啟 Alice
cargo run -- bob      # 會在 127.0.0.1:3001 上開啟 Bob
  </pre>
  <p>
    然後在瀏覽器分別開啟 <code>http://127.0.0.1:3000/</code> (Alice) 和
    <code>http://127.0.0.1:3001/</code> (Bob)。Alice 產生 JSON 傳給 Bob，
    Bob 也產生 JSON 傳回 Alice，兩邊都可以貼上對方的 JSON 計算共享密鑰。
  </p>

  <section>
    <h2>Step 1: 在本端產生自己的 JSON (本端的 Ephemeral Key + 簽名)</h2>
    <p>
      按下按鈕會在<strong>本端（{role_label}）</strong>產生一次性的 Diffie-Hellman 公鑰，
      並用本端的簽名私鑰對它簽名，結果會是 JSON。
      這個 JSON 要傳給對方（另一個瀏覽器分頁中的 {peer_label}）。
    </p>
    <form id="generate-form" method="post" action="/generate">
      <button type="submit">產生 JSON</button>
    </form>
    <p>產生後可以用 <code>/download-offer.json</code> 下載成檔案，再傳給對方。</p>
    <pre id="offer-json"></pre>
  </section>

  <section>
    <h2>Step 2: 在本端貼上<strong>對方 ({peer_label})</strong>傳來的 JSON，計算共享密鑰</h2>
    <form id="process-form" method="post" action="/process">
      <textarea name="json" placeholder="在這裡貼上對方給你的 JSON"></textarea>
      <br>
      <button type="submit">送出並驗證 + 計算共享密鑰</button>
    </form>
    <h3>結果</h3>
    <pre id="result"></pre>
  </section>

  <script>
    document.getElementById('generate-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const res = await fetch('/generate', {{ method: 'POST' }});
      if (!res.ok) {{
        document.getElementById('offer-json').textContent = 'Error: ' + res.status;
        return;
      }}
      const json = await res.json();
      document.getElementById('offer-json').textContent = JSON.stringify(json, null, 2);
    }});

    document.getElementById('process-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const data = new FormData(e.target);
      const jsonText = data.get('json');
      const res = await fetch('/process', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ json: jsonText }})
      }});
      const text = await res.text();
      document.getElementById('result').textContent = text;
    }});
  </script>
</body>
</html>
"#
    );

    Html(body)
}

async fn generate_offer(State(state): State<AppState>) -> Json<HandshakeMessage> {
    let dh = generate_dh_keypair();

    let eph_dec = dh.public.to_str_radix(10);
    let signature = sign_ephemeral(&state.longterm_signing.signing, &eph_dec);
    let msg = handshake_message_from_parts(
        &state.role,
        &eph_dec,
        &signature,
        &state.longterm_signing.verifying,
    );

    let mut dh_guard = state.dh_keys.lock().unwrap();
    *dh_guard = Some(dh);

    let mut last_offer_guard = state.last_offer.lock().unwrap();
    *last_offer_guard = Some(msg.clone());

    Json(msg)
}

async fn download_offer(State(state): State<AppState>) -> impl IntoResponse {
    let offer = {
        let guard = state.last_offer.lock().unwrap();
        guard.clone()
    };

    let Some(offer) = offer else {
        return (StatusCode::BAD_REQUEST, "尚未產生 JSON，請先在上方按下產生按鈕").into_response();
    };

    let body = serde_json::to_vec_pretty(&offer).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}-offer.json\"", state.role)
            .parse()
            .unwrap(),
    );

    (headers, body).into_response()
}

#[derive(Deserialize)]
struct ProcessRequest {
    json: String,
}

async fn process_response(
    State(state): State<AppState>,
    Json(payload): Json<ProcessRequest>,
) -> impl IntoResponse {
    let their_msg: HandshakeMessage = match serde_json::from_str(&payload.json) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("解析 JSON 失敗: {e}"),
            )
                .into_response()
        }
    };

    let (their_eph_pub, their_sig, their_verify) = match parse_handshake_message(&their_msg) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("解析對方 JSON 內容失敗: {e}"),
            )
                .into_response()
        }
    };

    if let Err(e) = verify_ephemeral_signature(&their_verify, &their_msg.ephemeral_public_dec, &their_sig) {
        return (
            StatusCode::BAD_REQUEST,
            format!("驗證對方簽名失敗: {e}"),
        )
            .into_response();
    }

    let my_dh = {
        let mut guard = state.dh_keys.lock().unwrap();
        guard.take()
    };

    let Some(my_dh) = my_dh else {
        return (
            StatusCode::BAD_REQUEST,
            "你這一端還沒有先產生自己的 JSON，請先按上面的按鈕產生一次。",
        )
            .into_response();
    };

    let shared = compute_shared_secret(&my_dh.secret, &their_eph_pub);
    let shared_hex = shared.to_str_radix(16);
    let aes_key = derive_aes256_key(&shared);
    let aes_hex = aes_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let aes_b64 = encode_b64(&aes_key);

    let response = format!(
        "對方身份簽名驗證成功。\n\
共享大整數密鑰 (hex): {shared_hex}\n\
\n\
從共享密鑰經 HKDF-SHA256 推導出的 AES‑256 key：\n\
  - AES key (hex):  {aes_hex}\n\
  - AES key (Base64): {aes_b64}\n\
\n\
提醒：雙方各自計算的共享密鑰（以及導出的 AES key）應該一致。你可以在 Alice / Bob 兩邊各自貼上對方 JSON，比對這裡顯示的值是否一樣。"
    );

    (StatusCode::OK, response).into_response()
}

fn mask_secret_preview(full_b64: &str) -> String {
    let len = full_b64.len();
    if len <= 16 {
        return full_b64.to_string();
    }
    let head = &full_b64[..8];
    let tail = &full_b64[len - 8..];
    format!("{head}**********{tail}")
}
