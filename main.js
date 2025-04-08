const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement } = require("./utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./checkAPI");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const { Wallet, ethers } = require("ethers");
const { jwtDecode } = require("jwt-decode");
const questions = loadData("questions.txt");
let REF_CODE = settings.REF_CODE;
let numberPerRef = settings.NUMBER_PER_REF;

class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL, authInfos) {
    this.headers = headers;
    this.baseURL = baseURL;
    this.baseURL_v2 = "";

    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.authInfos = authInfos;
    this.authInfo = { token: itemData.accessToken };
    this.localStorage = localStorage;
    this.wallet = new ethers.Wallet(this.itemData.privateKey);
    // this.w3 = new Web3(new Web3.providers.HttpProvider(settings.RPC_URL, proxy));
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_random_user_agent() {
    const randomIndex = Math.floor(Math.random() * user_agents.length);
    return user_agents[randomIndex];
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }

    console.log(`[Tài khoản ${this.accountIndex + 1}] Tạo user agent...`.blue);
    const newUserAgent = this.#get_random_user_agent();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[ByData][Account ${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 1,
      isAuth: false,
    }
  ) {
    const { retries, isAuth } = options;

    const headers = {
      ...this.headers,
    };

    if (!isAuth) {
      headers["authorization"] = `jwt ${this.token}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0,
      errorMessage = "",
      errorStatus = 0;
    do {
      try {
        const response = await axios({
          method,
          url: `${url}`,
          headers,
          timeout: 60000,
          ...(proxyAgent ? { httpsAgent: proxyAgent } : {}),
          ...(method.toLowerCase() != "get" ? { data: JSON.stringify(data || {}) } : {}),
        });
        if (response?.data?.data) return { status: response.status, success: true, data: response.data.data };
        return { success: true, data: response.data, status: response.status };
      } catch (error) {
        errorMessage = error?.response?.data || error.message;
        errorStatus = error.status;
        this.log(`Request failed: ${url} | ${JSON.stringify(errorMessage)}...`, "warning");

        if (error.message.includes("stream has been aborted")) {
          return { success: false, status: error.status, data: null, error: errorMessage };
        }
        if (error.status == 401) {
          const token = await this.getValidToken(true);
          if (!token) {
            process.exit(1);
          }
          this.token = token;
          return this.makeRequest(url, method, data, options);
        }
        if (error.status == 400) {
          this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: errorMessage, data: null };
        }
        if (error.status == 429) {
          this.log(`Rate limit ${error.message}, waiting 30s to retries`, "warning");
          await sleep(60);
        }
        await sleep(settings.DELAY_BETWEEN_REQUESTS);
        currRetries++;
        if (currRetries > retries) {
          return { status: error.status, success: false, error: errorMessage, data: null };
        }
      }
    } while (currRetries <= retries);
    return { status: errorStatus, success: false, error: errorMessage, data: null };
  }

  async auth() {
    const mess = "Welcome to Quack AI";
    const signedMessage = await this.wallet.signMessage(mess);
    const payload = { sign: signedMessage, address: this.itemData.address };
    return this.makeRequest(`${this.baseURL}/user/evm_connect`, "post", payload, { isAuth: true });
  }

  async getConversationsList() {
    return this.makeRequest(`${this.baseURL}/api/v1/conversations_list?address=${this.itemData.address}`, "get");
  }

  async getUserData() {
    return this.makeRequest(`${this.baseURL}/user/user_info?address=${this.itemData.address}`, "get");
  }

  async login() {
    return this.makeRequest(`${this.baseURL}/user`, "post", {
      wallet: this.itemData.address,
      invite: settings.REF_CODE,
    });
  }

  async bindInviteCode() {
    return this.makeRequest(`${this.baseURL}/user/bind_invite?inviteCode=${settings.REF_CODE}`, "get");
  }

  async sendMess(payload) {
    return this.makeRequest(`${this.baseURL}/api/v1/conversations`, "post", payload);
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);

    this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);
    if (existingToken && !isNew && !isExp) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, trying get new token...", "warning");
    const loginRes = await this.auth();
    if (!loginRes.success) return null;
    const newToken = loginRes.data;
    if (newToken?.token) {
      await saveJson(this.session_name, JSON.stringify(newToken), "tokens.json");
      return newToken.token;
    }
    this.log("Can't get new token...", "warning");
    return null;
  }

  async handleSyncData() {
    this.log(`Sync data...`);
    let userData = { success: true, data: null, status: 0 },
      retries = 0;

    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);
    if (userData?.success) {
      const { total_chat_count, chat_count, total_integral, invite_code, bindaddress } = userData.data;
      this.log(`Rate limit chat: ${chat_count}/${total_chat_count} |  Ref code: ${invite_code} | Total points: ${total_integral}`, "custom");
      if (!bindaddress && settings.REF_CODE != invite_code) {
        const bindRes = await this.bindInviteCode();
      }
    } else {
      return this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async handleChat(userData) {
    if (!questions || questions.length == 0) {
      return this.log("No questions found...skipping", "warning");
    }

    let { total_chat_count, chat_count } = userData;

    if (chat_count >= total_chat_count) return;
    const conversations = await this.getConversationsList();
    if (!conversations.success || !conversations.data) return this.log("Can't get conversations list...skipping", "warning");
    const { data } = conversations.data;

    if (data.length == 0) {
      this.log("No conversations found...Creating new conversation...", "warning");
      await sleep(1);
      const result = await this.sendMess({ query: "Hello", conversation_id: "", address: this.itemData.address });
      if (!result.success) return this.log("Can't create new conversation...skipping", "warning");
      this.log(`Created new conversation success!`, "success");
      return await this.handleChat(userData);
    }

    const thread = getRandomElement(data);
    const { id } = thread;

    while (chat_count < total_chat_count) {
      const timeSleep = getRandomNumber(settings.DELAY_CHAT[0], settings.DELAY_CHAT[1]);
      this.log(`Waiting ${timeSleep} seconds to send message...`, "info");
      await sleep(timeSleep);
      const message = getRandomElement(questions);
      this.log(`Chatting: ${message} | ID: ${id} | Chat count: ${chat_count}/${total_chat_count}`, "info");
      const payload = {
        query: message,
        conversation_id: id,
        address: this.itemData.address,
      };
      const res = await this.sendMess(payload);
      if (res.success) {
        chat_count++;
        this.log(`Chat success: ${chat_count}/${total_chat_count}`, "success");
      } else {
        this.log(`Chat failed: ${JSON.stringify(res)}`, "error");
      }
    }
  }
  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.authInfo = JSON.parse(this.authInfos[this.session_name] || "{}");
    this.token = this.authInfo?.token;
    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const token = await this.getValidToken();
    if (!token) return;
    this.token = token;
    const userData = await this.handleSyncData();
    if (userData.success) {
      await this.handleChat(userData.data);
      await sleep(1);
      await this.handleSyncData();
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI, authInfos } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI, authInfos);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  showBanner();
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");
  let authInfos = require("./tokens.json");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const resCheck = await checkBaseUrl();
  if (!resCheck.endpoint) return console.log(`Không thể tìm thấy ID API, có thể lỗi kết nỗi, thử lại sau!`.red);
  console.log(`${resCheck.message}`.yellow);

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      address: wallet.address,
      privateKey: prvk,
    };
    new ClientAPI(item, index, proxies[index], resCheck.endpoint, {}).createUserAgent();
    return item;
  });
  await sleep(1);
  while (true) {
    authInfos = require("./tokens.json");
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: resCheck.endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
            authInfos: authInfos,
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản | Chờ ${settings.TIME_SLEEP} phút=============`.magenta);
    showBanner();
    await sleep(settings.TIME_SLEEP * 60);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}
