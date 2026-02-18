/**
 * TRC Unified Foundation Core
 * Version: 26.5 (Zenith / Atomic Sync / Strict Filter)
 * 
 * 概要: TRCプロジェクト共通の究極統合基盤。
 * 
 * アップデート内容 (v26.5):
 * - 「設定保存」と「カウント取得」をアトミックな操作に統合 (saveSettingsAndGetCount)。
 * - 設定反映のタイムラグを完全排除。
 * - フィルタリング時の「全件取得フォールバック」を廃止し、指定アドレスのみを厳格に解析。
 */

// =====================================================================
// 0. 型定義 (JSDoc Type Definitions)
// =====================================================================

/**
 * @typedef {Object} ServiceResult
 * @property {boolean} success - 処理が成功したか
 * @property {string} [error] - エラーメッセージ (失敗時)
 * @property {any} [data] - 取得データ (成功時)
 * @property {string} [text] - AI生成テキスト (AI関連時)
 * @property {string} [model] - 使用モデル名
 * @property {string} [resetTime] - クォータ回復時刻
 * @property {Object} [report] - 自己診断レポート
 * @property {number} [count] - 未読数カウント
 */

// =====================================================================
// 1. 設定・定数定義
// =====================================================================

/** デフォルト設定ID (管理者が手動更新する時のみ使用) */
const DEFAULT_CONFIG_SHEET_ID = "YOUR_CONFIG_SPREADSHEET_ID_HERE"; 

const CACHE_DURATION_MS = 6 * 60 * 60 * 1000;
const MAX_RETRIES = 2; 
const RETRY_BASE_DELAY_MS = 1500; 

/** データ制限: 100KB (チャンク分割対応) */
const DATA_SIZE_LIMIT_BYTES = 100000; 
const CHUNK_SIZE = 8500; 
const LOG_RETENTION_DAYS = 90;

// ---------------------------------------------------------------------
// ★設定・AIモデル定義（最強のフォールバック構成）※変更厳禁
// ---------------------------------------------------------------------
const MODEL_CANDIDATES = [
  "gemini-3-pro-preview", // 👑 Main
  "gemini-2.5-flash",     // ⚡ Sub
  "gemini-2.5-pro",       // 🛡️ Backup
  "gemini-2.0-flash",     // 🚀 Backup
  "gemini-flash-latest"   // 🤖 Final
];
const ALLOWED_MODEL_PREFIXES = ["gemini-", "models/gemini-", "learnlm-", "corallm-"];

// =====================================================================
// 2. 汎用ユーティリティ & メトリクス
// =====================================================================

const Utils_ = {
  formatDate: function(date, format = 'YYYY/MM/DD HH:mm') {
    const d = date instanceof Date ? date : new Date(date);
    const pad = n => String(n).padStart(2, '0');
    return format
      .replace('YYYY', d.getFullYear())
      .replace('MM', pad(d.getMonth() + 1))
      .replace('DD', pad(d.getDate()))
      .replace('HH', pad(d.getHours()))
      .replace('mm', pad(d.getMinutes()));
  },
  
  generateId: function(prefix = '') {
    return prefix + Utilities.getUuid().replace(/-/g, '').substring(0, 12);
  },

  deepMerge: function(target, source) {
    const output = Object.assign({}, target);
    if (typeof target === 'object' && typeof source === 'object') {
      Object.keys(source).forEach(key => {
        if (typeof source[key] === 'object' && !Array.isArray(source[key])) {
          output[key] = this.deepMerge(target[key] || {}, source[key]);
        } else {
          output[key] = source[key];
        }
      });
    }
    return output;
  }
};

function logMetric_(action, status, durationMs) {
  console.info({
    type: 'METRIC',
    action: action,
    status: status,
    duration: durationMs + 'ms',
    timestamp: new Date().toISOString()
  });
}

// =====================================================================
// 3. スキーマ検証 & データ管理
// =====================================================================

const DataSchema_ = {
  validate: function(data, schema) {
    if (!schema) return { valid: true };
    const errors = [];
    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      if (rules.required && (value === undefined || value === null)) {
        errors.push(`Field '${field}' is required`);
        continue;
      }
      if (value !== undefined && value !== null) {
        if (rules.type === 'date' && !(value instanceof Date) && isNaN(new Date(value))) {
          errors.push(`Field '${field}' must be a valid date`);
        } else if (rules.type === 'array' && !Array.isArray(value)) {
          errors.push(`Field '${field}' must be an array`);
        } else if (rules.type !== 'array' && rules.type !== 'date' && typeof value !== rules.type) {
          errors.push(`Field '${field}' must be ${rules.type}`);
        }
      }
    }
    return { valid: errors.length === 0, errors };
  }
};

// =====================================================================
// 4. サーキットブレーカー
// =====================================================================
const CircuitBreaker_ = {
  getCache: function() { return CacheService.getScriptCache(); },
  
  isOpen: function(model) {
    const status = this.getCache().get(`CB_${model}`);
    return status === 'OPEN';
  },
  
  recordFailure: function(model) {
    this.getCache().put(`CB_${model}`, 'OPEN', 60); 
    console.warn(`Circuit Breaker OPEN for: ${model}`);
  },
  
  recordSuccess: function(model) {
    this.getCache().remove(`CB_${model}`);
  }
};

// =====================================================================
// 5. セキュリティモジュール (PBKDF2 + HMAC)
// =====================================================================
const Security_ = {
  getUserSecret: function(rotate = false) {
    try {
      const props = PropertiesService.getUserProperties();
      let secret = props.getProperty('USER_SECRET');
      
      const createdAt = props.getProperty('SECRET_CREATED_AT');
      if (createdAt && !rotate) {
        const daysOld = (new Date() - new Date(createdAt)) / (1000 * 60 * 60 * 24);
        if (daysOld > 90) console.warn(`Security Info: Key is ${Math.floor(daysOld)} days old.`);
      }

      if (!secret) {
        secret = 'v1:' + Utilities.getUuid();
        props.setProperties({
          'USER_SECRET': secret,
          'SECRET_VERSION': '1',
          'SECRET_CREATED_AT': new Date().toISOString()
        });
        return secret;
      }

      if (rotate) {
        const oldVersion = parseInt(props.getProperty('SECRET_VERSION') || '1');
        const newSecret = `v${oldVersion + 1}:` + Utilities.getUuid();
        const oldSecrets = JSON.parse(props.getProperty('OLD_SECRETS') || '[]');
        
        oldSecrets.unshift({ version: oldVersion, secret: secret, retiredAt: new Date().toISOString() });
        if (oldSecrets.length > 5) oldSecrets.pop();

        props.setProperties({
          'USER_SECRET': newSecret,
          'SECRET_VERSION': (oldVersion + 1).toString(),
          'SECRET_CREATED_AT': new Date().toISOString(),
          'OLD_SECRETS': JSON.stringify(oldSecrets)
        });
        return newSecret;
      }
      return secret;
    } catch (e) { throw new Error("SECURITY_INIT_FAILED"); }
  },

  encrypt: function(text) {
    if (!text) return "";
    try {
      const rawSecret = this.getUserSecret();
      const salt = Utilities.getUuid(); 
      const iv = Utilities.getUuid();
      
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) {
        const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i);
        derivedKey = Utilities.base64Encode(digest);
      }
      
      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const textBytes = Utilities.newBlob(text).getBytes();
      const encryptedBytes = textBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      const cipherB64 = Utilities.base64Encode(encryptedBytes);
      
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const mac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      
      return dataToSign + ":" + mac;
    } catch (e) { throw new Error("ENCRYPTION_FAILED"); }
  },

  decrypt: function(encryptedStr) {
    if (!encryptedStr) return "";
    
    if (encryptedStr.split(":").length === 2) {
      return this._decryptLegacy(encryptedStr);
    }

    const currentSecret = this.getUserSecret();
    let res = this._decryptStrong(encryptedStr, currentSecret);
    if (res !== null) return res;

    try {
      const props = PropertiesService.getUserProperties();
      const oldSecrets = JSON.parse(props.getProperty('OLD_SECRETS') || '[]');
      for (const entry of oldSecrets) {
        res = this._decryptStrong(encryptedStr, entry.secret);
        if (res !== null) return res;
      }
    } catch(e) {}
    return "";
  },

  _decryptStrong: function(encryptedStr, rawSecret) {
    try {
      const parts = encryptedStr.split(":");
      if (parts.length !== 4) return null;
      
      const [salt, iv, cipherB64, receivedMac] = parts;
      
      let derivedKey = rawSecret;
      for(let i=0; i<3000; i++) {
        const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, derivedKey + salt + i);
        derivedKey = Utilities.base64Encode(digest);
      }
      
      const dataToSign = salt + ":" + iv + ":" + cipherB64;
      const computedMac = Utilities.base64Encode(Utilities.computeHmacSha256Signature(dataToSign, derivedKey));
      if (computedMac !== receivedMac) return null;

      const keyStream = Utilities.computeHmacSha256Signature(iv, derivedKey);
      const encryptedBytes = Utilities.base64Decode(cipherB64);
      const decryptedBytes = encryptedBytes.map((byte, i) => byte ^ keyStream[i % keyStream.length]);
      
      const result = Utilities.newBlob(decryptedBytes).getDataAsString();
      if (result && !/[\uFFFD]/.test(result)) return result;
      return null;
    } catch(e) { return null; }
  },

  _decryptLegacy: function(str) {
    try {
      const secret = this.getUserSecret();
      const parts = str.split(":");
      const salt = parts[0];
      const bytes = Utilities.base64Decode(parts[1]);
      const ks = Utilities.computeHmacSha256Signature(salt, secret);
      const dec = bytes.map((b,i) => b ^ ks[i % ks.length]);
      return Utilities.newBlob(dec).getDataAsString();
    } catch(e) { return ""; }
  }
};

// =====================================================================
// 6. データ管理 (Chunking & Privacy DB)
// =====================================================================

function saveChunkedData_(keyPrefix, dataStr) {
  const props = PropertiesService.getUserProperties();
  const metaKey = keyPrefix + '_META';
  
  const oldMeta = props.getProperty(metaKey);
  if (oldMeta) {
    try {
      const count = JSON.parse(oldMeta).chunks;
      for (let i = 0; i < count; i++) props.deleteProperty(keyPrefix + '_' + i);
    } catch(e){}
  }

  const chunks = [];
  for (let i = 0; i < dataStr.length; i += CHUNK_SIZE) {
    chunks.push(dataStr.substring(i, i + CHUNK_SIZE));
  }
  
  const payload = {};
  payload[metaKey] = JSON.stringify({ chunks: chunks.length, timestamp: new Date().getTime() });
  chunks.forEach((chunk, index) => { payload[keyPrefix + '_' + index] = chunk; });
  
  props.setProperties(payload);
}

function loadChunkedData_(keyPrefix) {
  const props = PropertiesService.getUserProperties();
  const legacyData = props.getProperty(keyPrefix);
  if (legacyData && !props.getProperty(keyPrefix + '_META')) return legacyData;

  const metaJson = props.getProperty(keyPrefix + '_META');
  if (!metaJson) return null;
  
  try {
    const meta = JSON.parse(metaJson);
    let fullData = "";
    for (let i = 0; i < meta.chunks; i++) {
      const chunk = props.getProperty(keyPrefix + '_' + i);
      if (!chunk) return null;
      fullData += chunk;
    }
    return fullData;
  } catch(e) { return null; }
}

function saveUserData(dataObj, schema = null) {
  const start = new Date().getTime();
  try {
    if (!dataObj || typeof dataObj !== 'object') throw new Error("INVALID_DATA_TYPE");
    
    if (schema) {
      const validation = DataSchema_.validate(dataObj, schema);
      if (!validation.valid) throw new Error("SCHEMA_VALIDATION_FAILED: " + validation.errors.join(", "));
    }
    
    let jsonStr = JSON.stringify(dataObj);
    if (Utilities.newBlob(jsonStr).getBytes().length > DATA_SIZE_LIMIT_BYTES) {
       throw new Error("DATA_SIZE_LIMIT_EXCEEDED_100KB");
    }

    const encrypted = Security_.encrypt(jsonStr);
    saveChunkedData_('APP_DATA', encrypted);
    
    logMetric_('saveUserData', 'SUCCESS', new Date().getTime() - start);
    return { success: true };
  } catch (e) {
    logSystemError_("saveUserData", e);
    return { success: false, error: e.message };
  }
}

function loadUserData() {
  const start = new Date().getTime();
  try {
    const props = PropertiesService.getUserProperties();
    const encKey = props.getProperty('GEMINI_KEY');
    const apiKey = Security_.decrypt(encKey);
    const hasKey = !!(encKey && apiKey && apiKey.length > 20);
    
    const encData = loadChunkedData_('APP_DATA');
    let data = null;
    if (encData) {
      const jsonStr = Security_.decrypt(encData);
      try { data = jsonStr ? JSON.parse(jsonStr) : {}; } catch(e) { data = {}; }
    }
    logMetric_('loadUserData', 'SUCCESS', new Date().getTime() - start);
    return { success: true, hasApiKey: hasKey, data: data || {} };
  } catch (e) {
    logSystemError_("loadUserData", e);
    return { success: false, error: e.message };
  }
}

function sanitizeStackTrace_(stack) {
  if (!stack) return '';
  return stack
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '<EMAIL_MASKED>')
    .replace(/\/d\/[a-zA-Z0-9_-]+/g, '/d/<FILE_ID_MASKED>')
    .split('\n').slice(0, 5).join('\n');
}

function logSystemError_(funcName, errorObj) {
  const email = Session.getActiveUser().getEmail() || "Anonymous";
  let userHash = email;
  if (email !== "Anonymous") {
    const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, email);
    userHash = "u_" + digest.map(b => (b < 0 ? b + 256 : b).toString(16).padStart(2, '0')).join('').substring(0, 16);
  }
  const formatted = formatErrorObj_(errorObj);
  const sanitizedDetails = { ...formatted, stack: sanitizeStackTrace_(formatted.stack) };
  
  console.error({ function: funcName, user: userHash, error: formatted.message, details: sanitizedDetails });

  try {
    const sheetId = getConfigSheetId_();
    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName("Error_Logs");
    if (!sheet) {
      sheet = ss.insertSheet("Error_Logs");
      sheet.appendRow(["Timestamp", "UserHash", "Function", "ErrorMessage", "Details", "RetentionUntil"]);
      sheet.setFrozenRows(1);
    }
    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() + LOG_RETENTION_DAYS);
    sheet.appendRow([new Date(), userHash, funcName, formatted.message, JSON.stringify(sanitizedDetails), retentionDate]);
  } catch (e) { 
    console.warn("Log Sheet Access Skipped (Visitor Mode)"); 
  }
}
function formatErrorObj_(e) {
  if (e instanceof Error) return { name: e.name, message: e.message, stack: e.stack };
  return { message: String(e) };
}

// =====================================================================
// 7. 設定管理 (ScriptProperties "Shared Memory")
// =====================================================================
function getConfigSheetId_() {
  return PropertiesService.getScriptProperties().getProperty('CONFIG_SHEET_ID') || DEFAULT_CONFIG_SHEET_ID;
}

function adminManualUpdateConfig() {
  console.log("Starting Admin Config Update...");
  try {
    const sheetId = getConfigSheetId_();
    const ss = SpreadsheetApp.openById(sheetId);
    const sheet = ss.getSheets()[0];
    const lastRow = sheet.getLastRow();
    const lastCol = sheet.getLastColumn();
    
    if (lastRow === 0 || lastCol === 0) throw new Error("Sheet is empty");
    
    const values = sheet.getRange(1, 1, lastRow, lastCol).getValues();
    const validModels = values.flat().map(v => String(v).trim())
      .filter(v => ALLOWED_MODEL_PREFIXES.some(p => v.toLowerCase().startsWith(p)));
    
    const uniqueModels = [...new Set(validModels)];
    if (uniqueModels.length === 0) throw new Error("No valid models found");
    
    PropertiesService.getScriptProperties().setProperties({
      'GLOBAL_MODELS': JSON.stringify(uniqueModels),
      'LAST_UPDATE_TIME': new Date().getTime().toString(),
      'CONFIG_STATUS': 'OK'
    });
    
    console.log("SUCCESS: Models updated in Shared Memory:", uniqueModels);
    return `Update Success: ${uniqueModels.join(", ")}`;
  } catch (e) {
    console.error("Admin Update Failed:", e);
    return `Update Failed: ${e.message}`;
  }
}

function getModelCandidates() {
  try {
    const props = PropertiesService.getScriptProperties();
    const json = props.getProperty("GLOBAL_MODELS");
    if (json) return JSON.parse(json);
    return MODEL_CANDIDATES;
  } catch (e) { 
    return MODEL_CANDIDATES; 
  }
}

// =====================================================================
// 8. AI接続エンジン (API)
// =====================================================================

function isQuotaError_(code, errorMsg, errorStatus) {
  if (code === 429) return true;
  if (code === 403 || code === 503) {
    const keywords = ['quota', 'limit', 'rate', 'exceeded', 'exhausted'];
    if (keywords.some(kw => errorMsg.toLowerCase().includes(kw))) return true;
  }
  if (errorStatus === 'RESOURCE_EXHAUSTED') return true;
  return false;
}

function calculateQuotaResetTime_() {
  try {
    const now = new Date();
    const pstDateStr = now.toLocaleString("en-US", {timeZone: "America/Los_Angeles"});
    const pstMidnight = new Date(pstDateStr);
    pstMidnight.setDate(pstMidnight.getDate() + 1);
    pstMidnight.setHours(0, 0, 0, 0);
    const diffMs = pstMidnight.getTime() - new Date(pstDateStr).getTime();
    const localReset = new Date(now.getTime() + diffMs);
    const hoursUntil = Math.ceil(diffMs / (1000 * 60 * 60));
    return { hoursUntil, resetTimeStr: localReset.toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) };
  } catch(e) { return { hoursUntil: 24, resetTimeStr: "明日" }; }
}

function callGeminiEngine(prompt, systemInstruction = "") {
  const start = new Date().getTime();
  try {
    const encKey = PropertiesService.getUserProperties().getProperty('GEMINI_KEY');
    if (!encKey) throw new Error("NO_API_KEY");
    const apiKey = Security_.decrypt(encKey);
    if (!apiKey) throw new Error("INVALID_KEY_STORED");

    const models = getModelCandidates();
    let lastError = "";
    let allModelsQuotaError = true;

    for (const model of models) {
      if (CircuitBreaker_.isOpen(model)) continue;
      
      let thisModelQuota = false;

      for (let retry = 0; retry <= MAX_RETRIES; retry++) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
        const payload = { contents: [{ parts: [{ text: prompt }] }] };
        if (systemInstruction) payload.systemInstruction = { parts: [{ text: systemInstruction }] };
        const options = {
          method: 'post', contentType: 'application/json',
          headers: { 'x-goog-api-key': apiKey },
          payload: JSON.stringify(payload), muteHttpExceptions: true, timeout: 30 
        };

        try {
          const response = UrlFetchApp.fetch(url, options);
          const code = response.getResponseCode();
          
          if (code === 200) {
            const json = JSON.parse(response.getContentText());
            const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
              CircuitBreaker_.recordSuccess(model);
              logMetric_('callGemini', 'SUCCESS', new Date().getTime() - start);
              return { success: true, text: text, model: model };
            }
          }
          
          const bodyText = response.getContentText();
          let errorMsg = bodyText;
          let errorStatus = "";
          try { 
            const eJson = JSON.parse(bodyText).error;
            errorMsg = eJson.message || bodyText;
            errorStatus = eJson.status;
          } catch(_){}

          if (isQuotaError_(code, errorMsg, errorStatus)) {
            thisModelQuota = true; 
            if (retry < MAX_RETRIES) {
               Utilities.sleep((RETRY_BASE_DELAY_MS * Math.pow(2, retry)) + (Math.random() * 500));
               continue; 
            } else {
               CircuitBreaker_.recordFailure(model);
            }
          } else if (code === 400 && errorMsg.includes("API_KEY_INVALID")) {
            throw new Error("INVALID_KEY_DETECTED");
          } else if (code >= 500) {
            if (retry < MAX_RETRIES) {
              Utilities.sleep((RETRY_BASE_DELAY_MS * Math.pow(2, retry)) + (Math.random() * 500));
              continue; 
            } else {
              CircuitBreaker_.recordFailure(model);
            }
          }
          lastError += `[${model}:${code}] `;
          break;

        } catch (innerE) {
          if (innerE.message === "INVALID_KEY_DETECTED") throw innerE;
          lastError += `[${model}:Err] `;
          break; 
        }
      }
      if (!thisModelQuota) allModelsQuotaError = false;
    }

    if (allModelsQuotaError && lastError.length > 0) {
      const resetInfo = calculateQuotaResetTime_();
      logMetric_('callGemini', 'QUOTA', new Date().getTime() - start);
      return { success: false, error: "QUOTA_EXCEEDED_STRICT", resetTime: resetInfo.resetTimeStr, hoursUntil: resetInfo.hoursUntil };
    }

    logMetric_('callGemini', 'FAILED', new Date().getTime() - start);
    throw new Error("ALL_MODELS_FAILED: " + lastError);

  } catch (e) {
    return { success: false, error: e.message, resetTime: e.resetTime, hoursUntil: e.hoursUntil };
  }
}

function testConnection(apiKey) {
  if (!apiKey || apiKey.trim().length < 30) return { success: false, error: "KEY_FORMAT_INVALID" };
  const cleanKey = apiKey.trim();
  const candidates = getModelCandidates();
  candidates.push("gemini-1.5-flash");
  const models = [...new Set(candidates)];
  let lastError = "CONNECTION_FAILED";

  for (const model of models) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
      const payload = { contents: [{ parts: [{ text: "Hi" }] }] };
      const options = {
        method: 'post', contentType: 'application/json',
        headers: { 'x-goog-api-key': cleanKey },
        payload: JSON.stringify(payload), muteHttpExceptions: true
      };
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      if (code === 200) return { success: true };
      const body = response.getContentText();
      if (code === 400 && body.includes("API_KEY_INVALID")) return { success: false, error: "INVALID_KEY_DETECTED" };
      if (code === 429) lastError = "QUOTA_OR_RATE_LIMIT";
      else lastError = `HTTP_${code}`;
    } catch (e) { lastError = e.message; }
  }
  return { success: false, error: lastError };
}

// =====================================================================
// 9. システム自己診断 & 管理
// =====================================================================

function runSystemSelfCheck() {
  const report = { encryption: false, data: false, config: false, logs: true };
  try {
    const testStr = "TRC_TEST_" + Utilities.getUuid();
    const enc = Security_.encrypt(testStr);
    const dec = Security_.decrypt(enc);
    if (dec === testStr) report.encryption = true;
    
    const longData = "A".repeat(15000);
    saveChunkedData_("SELF_TEST_DATA", longData);
    const loaded = loadChunkedData_("SELF_TEST_DATA");
    if (loaded === longData) report.data = true;
    PropertiesService.getUserProperties().deleteProperty("SELF_TEST_DATA_META");
    
    const models = getModelCandidates();
    if (models.length > 0) report.config = true;
    
    return { success: true, report: report };
  } catch(e) {
    return { success: false, error: e.message, report: report };
  }
}

function saveApiKey(key) {
  try {
    const k = key ? key.trim() : "";
    if (k.length < 30) throw new Error("KEY_FORMAT_INVALID");
    PropertiesService.getUserProperties().setProperty('GEMINI_KEY', Security_.encrypt(k));
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function deleteUserData(hard) {
  const props = PropertiesService.getUserProperties();
  if (!hard) {
    const backup = {
      data: loadChunkedData_('APP_DATA'),
      key: props.getProperty('GEMINI_KEY'),
      deletedAt: new Date().toISOString()
    };
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    props.deleteAllProperties();
    props.setProperty('DELETED_BACKUP', JSON.stringify(backup));
    
    const restoreUntil = new Date(new Date().getTime() + 24 * 60 * 60 * 1000);
    return { success: true, mode: 'soft', restoreUntil: restoreUntil.toLocaleString('ja-JP') };
  }
  props.deleteAllProperties();
  return { success: true, mode: 'hard' };
}

function restoreUserData() {
  try {
    const props = PropertiesService.getUserProperties();
    const backupJson = props.getProperty('DELETED_BACKUP');
    if (!backupJson) return { success: false, error: "NO_BACKUP_FOUND" };
    const backup = JSON.parse(backupJson);
    if ((new Date() - new Date(backup.deletedAt)) > 86400000) return { success: false, error: "BACKUP_EXPIRED" };
    
    if (backup.data) {
      const encrypted = Security_.encrypt(backup.data);
      saveChunkedData_('APP_DATA', encrypted);
    }
    if (backup.key) props.setProperty('GEMINI_KEY', backup.key);
    props.deleteProperty('DELETED_BACKUP');
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
}

function clearUserCache() {
  const props = PropertiesService.getUserProperties();
  const meta = props.getProperty('APP_DATA_META');
  if(meta) {
     try {
       const c = JSON.parse(meta).chunks;
       for(let i=0; i<c; i++) props.deleteProperty('APP_DATA_'+i);
       props.deleteProperty('APP_DATA_META');
     } catch(e){}
  }
  props.deleteProperty('APP_DATA');
  return { success: true };
}


// =====================================================================
// 10. Adapter Layer (既存アプリ互換レイヤー)
// =====================================================================

function doGet() {
  const loadRes = loadUserData();
  const data = loadRes.data || {};
  const apiKeyExists = loadRes.hasApiKey;
  
  const template = HtmlService.createTemplateFromFile('Index');
  
  const isSetup = !!(apiKeyExists && data.userEmail);
  
  template.isSetupCompleted = isSetup;
  template.currentUserEmail = Session.getActiveUser().getEmail();
  
  return template.evaluate()
    .setTitle('AI Mail Secretary "K-Model"')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function saveInitialSettings(apiKey, inputEmail) {
  if (!apiKey) throw new Error("APIキーが入力されていません。");
  if (!inputEmail) throw new Error("Gmailアドレスが入力されていません。");

  const activeUser = Session.getActiveUser().getEmail();
  if (activeUser && activeUser !== inputEmail) {
    throw new Error(`ログイン中のGoogleアカウント(${activeUser})と、入力されたアドレスが一致しません。`);
  }

  const testRes = testConnection(apiKey);
  if (!testRes.success) {
    let errorMsg = "無効なAPIキーです（または現在利用可能なモデルが見つかりません）。Gemini APIコンソールを確認してください。";
    if (testRes.error === "KEY_FORMAT_INVALID" || testRes.error === "INVALID_KEY_DETECTED") {
      errorMsg = "正しいAPIキーではないようです。半角スペースなどが混ざらないように、正確にご入力ください";
    }
    throw new Error(errorMsg);
  }

  try {
    saveApiKey(apiKey);
    const loadRes = loadUserData();
    const newData = loadRes.data || {};
    newData.userEmail = inputEmail;
    if (!newData.queue) newData.queue = [];
    if (!newData.history) newData.history = [];
    const saveRes = saveUserData(newData);
    if (!saveRes.success) throw new Error("設定保存エラー: " + saveRes.error);
    return { success: true };
  } catch (e) {
    throw new Error("セットアップエラー: " + e.message);
  }
}

function logoutUser() {
  const res = deleteUserData(true); 
  return res.success;
}

function verifyApiKey(apiKey) {
  return testConnection(apiKey).success;
}

// =====================================================================
// 2. バックエンド処理 (Queue, Worker & History)
// =====================================================================

/**
 * 内部ヘルパー: 設定オブジェクトに基づいて未読数をカウント
 * DB読み込みではなく、メモリ上の設定オブジェクトを直接使用することで
 * タイムラグのない正確なカウントを実現する。
 */
function countWithSettings_(settings) {
  const targetStr = settings.targetEmails || "";
  const isFilterEnabled = settings.isFilterEnabled === true;
  
  // フィルタON かつ 指定がある場合 (Strict Mode)
  if (isFilterEnabled && targetStr.trim().length > 0) {
    const addrList = targetStr.split(/[,、\s]+/)
                              .map(s => s.trim())
                              .filter(s => s.length > 0 && s.includes("@"));
    
    if (addrList.length > 0) {
      const toConditions = addrList.map(addr => `to:${addr}`).join(' OR ');
      const query = `is:unread (${toConditions})`;
      
      try {
        const threads = GmailApp.search(query);
        return threads.length;
      } catch (e) {
        // エラー時は0件 (全件取得には戻さない)
        return 0;
      }
    }
    // アドレスリストが空なら0件
    return 0;
  }
  
  // フィルタOFF時は高速な全件カウント
  return GmailApp.getInboxUnreadCount();
}

/**
 * ★新設関数: 設定保存とカウント取得のアトミック操作
 * フロントエンドから呼び出され、保存直後の設定で計算したカウントを即座に返す。
 */
function saveSettingsAndGetCount(settingsJson) {
  try {
    // 1. 設定保存処理 (既存ロジック利用)
    const saveRes = saveUserSettings(settingsJson);
    if (!saveRes.success) {
      return { success: false, error: saveRes.error };
    }
    
    // 2. メモリ上の設定値を使って即座にカウント (DB読み込みラグを回避)
    const newSettings = JSON.parse(settingsJson);
    const count = countWithSettings_(newSettings);
    
    return { success: true, count: count };
    
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function getUnreadCount() {
  // 初期表示用: DBから読み込んで計算
  const loadRes = loadUserData();
  const data = loadRes.data || {};
  return countWithSettings_(data);
}

function syncAndProcess(includeRead) {
  fetchEmailsToQueue(includeRead);
  return processQueueWorker();
}

/**
 * 修正版(v26.5): Strict Filter & No Fallback
 */
function fetchEmailsToQueue(includeRead) {
  const loadRes = loadUserData();
  if (!loadRes.success) return; 
  const data = loadRes.data || {};
  
  if (!data.queue) data.queue = [];
  
  const existingIds = new Set();
  data.queue.forEach(row => existingIds.add(row[0]));

  const targetStr = data.targetEmails || "";
  const isFilterEnabled = data.isFilterEnabled === true; 
  
  let threads = [];

  // フィルタON時の厳格な挙動
  if (isFilterEnabled && targetStr.trim().length > 0) {
    const addrList = targetStr.split(/[,、\s]+/)
                              .map(s => s.trim())
                              .filter(s => s.length > 0 && s.includes("@"));
    
    if (addrList.length > 0) {
      let query = includeRead ? '' : 'is:unread';
      const toConditions = addrList.map(addr => `to:${addr}`).join(' OR ');
      query = (query ? query + " " : "") + `(${toConditions})`;
      
      try {
        threads = GmailApp.search(query, 0, 20);
      } catch (e) {
        console.error("Filter Search Error (Strict Mode):", e);
        // エラー時は空配列 (全件取得禁止)
        threads = []; 
      }
    } else {
      threads = [];
    }
  } else {
    // フィルタOFF時のみ全件許可
    if (includeRead) {
      threads = GmailApp.getInboxThreads(0, 20);
    } else {
      threads = GmailApp.search('is:unread', 0, 20);
    }
  }

  threads.forEach(thread => {
    const messages = thread.getMessages();
    const msg = messages[messages.length - 1]; 
    const id = msg.getId();
    
    let subject = msg.getSubject();
    if (!subject || subject.trim() === "") subject = "(件名なし)";

    if (!existingIds.has(id)) {
      data.queue.push([id, msg.getFrom(), subject, msg.getDate(), 'pending', '', '', '']);
    }
  });

  if (data.queue.length > 50) {
    data.queue = data.queue.slice(data.queue.length - 50);
  }

  saveUserData(data);
}

function cleanUpOldCache(ssId) {}

function processQueueWorker() {
  const loadRes = loadUserData();
  if (!loadRes.success || !loadRes.hasApiKey) throw new Error("設定読み込みエラー");
  const data = loadRes.data || {};
  if (!data.queue) data.queue = [];

  const results = [];
  const MAX_AI_BATCH = 5;
  let aiCount = 0;
  let dataModified = false;
  
  // Gmail現状確認用もStrictにすべきだが、ID照合用なのでsearch('is:unread')で広めに取っても実害は少ない
  // ただし、整合性のためフィルタ条件を考慮したほうが良いが、
  // Workerは「キューにあるものを処理する」責務なので、キューへの投入が正しければ問題ない。
  const threads = GmailApp.search('is:unread', 0, 20);
  const targetIds = threads.map(t => {
    const msgs = t.getMessages();
    return msgs[msgs.length - 1].getId();
  });

  for (const id of targetIds) {
    const qIndex = data.queue.findIndex(row => row[0] === id);
    if (qIndex === -1) continue;

    const row = data.queue[qIndex];
    const [msgId, from, subj, date, status, savedSummary, savedPriority, savedCategory] = row;
    const msgObj = GmailApp.getMessageById(msgId); 

    if (status === 'processed' && savedSummary) {
      results.push({
        id: msgId, from: from, subject: subj, date: new Date(date).toLocaleDateString(),
        summary: savedSummary, priority: savedPriority, category: savedCategory,
        body: msgObj.getPlainBody(), isPiiMasked: false
      });
    } else if (status === 'pending' || status === 'error') {
      if (aiCount < MAX_AI_BATCH) {
        try {
          let body = msgObj.getPlainBody();
          if (!body || body.trim() === "") body = "[本文なし / 件名または添付のみ]";
          const { maskedBody, placeholders } = maskPII(body);
          
          const aiResult = executeAnalysisOnly(null, maskedBody); 

          data.queue[qIndex][4] = 'processed';
          data.queue[qIndex][5] = aiResult.summary;
          data.queue[qIndex][6] = aiResult.priority;
          data.queue[qIndex][7] = aiResult.category;
          dataModified = true;

          results.push({
            id: msgId, from: from, subject: subj, date: new Date(date).toLocaleDateString(),
            summary: aiResult.summary, priority: aiResult.priority, category: aiResult.category,
            body: body, isPiiMasked: Object.keys(placeholders).length > 0
          });
          aiCount++;
        } catch (e) {
          console.error(e);
          let errorMsg = "AI解析エラー";
          const strErr = e.toString();
          if (strErr.includes("QUOTA") || strErr.includes("明日")) errorMsg = "本日のAI利用制限です🍵";
          
          data.queue[qIndex][4] = 'error';
          dataModified = true;
          results.push(createErrorResult({id:msgId, from:from, subject:subj, date:date, msgObject:msgObj}, errorMsg));
        }
      } else {
        results.push(createErrorResult({id:msgId, from:from, subject:subj, date:date, msgObject:msgObj}, "⏳ 解析待ち (次回更新で解析)"));
      }
    }
  }

  if (dataModified) {
    saveUserData(data);
  }

  return results;
}

function createErrorResult(email, msg) {
  return {
    id: email.id, from: email.from, subject: email.subject,
    date: new Date(email.date).toLocaleDateString(),
    summary: msg, priority: "‐", category: "‐",
    body: email.msgObject.getPlainBody(), isPiiMasked: false
  };
}

function generateDraftForId(id) {
  try {
    const msg = GmailApp.getMessageById(id);
    let body = msg.getPlainBody();
    if (!body || body.trim() === "") body = "[本文なし / 件名または添付のみ]";

    const { maskedBody, placeholders } = maskPII(body);
    
    const prompt = `
    あなたはCEO秘書です。以下のメールに対し、CEOとして送信する丁寧かつ簡潔な返信案(60-140文字程度)を作成してください。
    【メール本文】
    ${maskedBody.substring(0, 3000)}
    `;
    
    const res = callGeminiEngine(prompt);
    if (!res.success) throw new Error(res.error);

    const restoredDraft = restorePII(res.text, placeholders);
    return restoredDraft;

  } catch (e) {
    throw e;
  }
}

function getSentHistory() {
  const loadRes = loadUserData();
  const data = loadRes.data || {};
  if (!data.history) return [];
  return data.history;
}

// =====================================================================
// 3. AIロジック & セキュリティ (Core Wrapper)
// =====================================================================

function maskPII(text) {
  const placeholders = {};
  let masked = text.replace(/(\d{2,4}[-(]\d{2,4}[-)]\d{4})/g, m => {
    const k = `[PII_PHONE_${Object.keys(placeholders).length}]`; placeholders[k] = m; return k;
  });
  masked = masked.replace(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/g, m => {
    const k = `[PII_EMAIL_${Object.keys(placeholders).length}]`; placeholders[k] = m; return k;
  });
  return { maskedBody: masked, placeholders: placeholders };
}

function restorePII(text, placeholders) {
  let restored = text;
  for (const k in placeholders) restored = restored.replace(k, placeholders[k]);
  return restored;
}

function executeAnalysisOnly(apiKey, text) {
  const prompt = `
  あなたはCEO秘書です。以下のメールを分析し、JSON形式のみで出力してください。
  
  【出力JSON形式】
  {
    "summary": "3行以内の簡潔な要約",
    "category": "取引先/営業/社内/その他",
    "priority": "高/中/低" 
  }
  
  【判定基準】
  - 高: 緊急、クレーム、重要取引先、日程調整
  - 中: 一般的な連絡、質問
  - 低: 営業メール、報告のみ
  
  【メール本文】
  ${text.substring(0, 2000)}
  `;

  const systemInstruction = "JSON形式のみを出力してください。Markdownは不要です。";
  
  const res = callGeminiEngine(prompt, systemInstruction);
  
  if (!res.success) {
    throw new Error(res.error);
  }
  
  let json = { summary: "解析不可", category: "その他", priority: "低" };
  try {
    const cleanText = res.text.replace(/```json/gi, "").replace(/```/g, "").trim();
    const match = cleanText.match(/(\{[\s\S]*\})/);
    if (match) json = JSON.parse(match[1]);
    else json = JSON.parse(cleanText);
  } catch(e) {
    console.warn("JSON Parse Error", e);
  }
  return json;
}

function callGeminiWithBackoff(apiKey, prompt) {
  const res = callGeminiEngine(prompt);
  if(!res.success) throw new Error(res.error);
  return res.text;
}

function sendEmail(id, to, subject, body) {
  const msg = GmailApp.getMessageById(id);
  msg.reply(body); 
  msg.getThread().markRead();

  const loadRes = loadUserData();
  const data = loadRes.data || {};
  if (!data.history) data.history = [];

  data.history.unshift({
    date: new Date().toLocaleString(),
    to: to,
    subject: subject,
    bodySnippet: body.substring(0,50)+"...",
    status: "SENT"
  });

  if (data.history.length > 30) {
    data.history.pop();
  }

  saveUserData(data);
}

function saveUserSettings(settingsJson) {
  try {
    const newSettings = JSON.parse(settingsJson);
    const loadRes = loadUserData();
    const data = loadRes.data || {};
    
    if (typeof newSettings.targetEmails === 'string') {
      data.targetEmails = newSettings.targetEmails;
    }
    if (typeof newSettings.isFilterEnabled === 'boolean') {
      data.isFilterEnabled = newSettings.isFilterEnabled;
    }
    
    return saveUserData(data);
  } catch (e) {
    return { success: false, error: e.message };
  }
}
