import * as fs from 'fs';
import vm from 'node:vm';

import * as path from 'path';
import { fileURLToPath } from 'url';
import { CAS, CA_CERTIFICATES, PKEY_PARAMETERS } from './consts.js';

// Определяем __dirname и __filename
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// window
if (!('window' in globalThis)) {
    Object.defineProperty(globalThis, 'window', {
      value: globalThis,
      writable: false,
      enumerable: false,
      configurable: true,
    });
  }
  
  // navigator
  (() => {
    const desc = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    if (!desc) {
      Object.defineProperty(globalThis, 'navigator', {
        value: { appName: 'nodejs', userAgent: `node/${process.version}` },
        writable: false,
        enumerable: true,
        configurable: true,
      });
    } else if (desc.configurable && !('userAgent' in globalThis.navigator)) {
      Object.defineProperty(globalThis, 'navigator', {
        value: { ...globalThis.navigator, appName: 'nodejs', userAgent: `node/${process.version}` },
        writable: false,
        enumerable: true,
        configurable: true,
      });
    }
  })();
  
  // eu_wait — ДЕЛАЕМ ПЕРЕЗАПИСЫВАЕМЫМ
  if (typeof globalThis.eu_wait !== 'function') {
    Object.defineProperty(globalThis, 'eu_wait', {
      value: function (msec) {
        const end = Date.now() + (Number(msec) || 0);
        while (Date.now() < end) {}
      },
      writable: true,          // важно
      enumerable: false,
      configurable: true,
    });
  }
  
  // Коллбек — тоже перезаписываемый
  let g_isLibraryLoaded = false;
  function _EUSignCPModuleInitialized(isInitialized) {
    g_isLibraryLoaded = !!isInitialized;
  }
  Object.defineProperty(globalThis, 'EUSignCPModuleInitialized', {
    value: _EUSignCPModuleInitialized,
    writable: true,            // важно
    enumerable: false,
    configurable: true,
  });
  
  // base64-шимы (можно неизменяемыми)
  if (typeof globalThis.atob !== 'function') {
    Object.defineProperty(globalThis, 'atob', {
      value: (b64) => Buffer.from(b64, 'base64').toString('binary'),
      writable: false, enumerable: false, configurable: true,
    });
  }
  if (typeof globalThis.btoa !== 'function') {
    Object.defineProperty(globalThis, 'btoa', {
      value: (str) => Buffer.from(str, 'binary').toString('base64'),
      writable: false, enumerable: false, configurable: true,
    });
  }
  
  /* ===== Загрузка криптолибы с нормальным стеком ===== */
  
  function loadScript(file) {
    const code = fs.readFileSync(path.resolve(__dirname, file), 'utf8');
    // отдельный Script с именем файла — стек бэктрейса будет понятным
    vm.runInThisContext(code, { filename: path.resolve(__dirname, file) });
  }
  
  // избегаем двойной загрузки
  if (!globalThis.__eusign_loaded__) {
    loadScript('./euscpt.js');
    loadScript('./euscpm.js');
    loadScript('./euscp.js');
    Object.defineProperty(globalThis, '__eusign_loaded__', {
      value: true, writable: false, enumerable: false, configurable: true,
    });
  }
  
  // Жестче контролируем ожидание инициализации
  function waitLibraryInit(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      (function tick() {
        if (g_isLibraryLoaded) return resolve();
        if (Date.now() - start >= timeoutMs) return reject(new Error('EUSignCP init timeout'));
        setTimeout(tick, 1);
      })();
    });
  }
  
  export function EUSignCPModuleInitialized(isInitialized) {
    g_isLibraryLoaded = !!isInitialized;
  }

class EndUserSignModule {
  constructor(CAs, CACertificates, PKeySettings) {
    this.euSign = EUSignCP();
    this.context = null;
    this.pkContext = null;
    this.CAs = CAs;
    this.CACertificates = CACertificates;
    this.PKeySettings = PKeySettings;
  }

  _load() {
    return new Promise((resolve) => {
      const check = () => (g_isLibraryLoaded ? resolve() : setTimeout(check, 1));
      check();
    });
  }

  async _initialize() {
    const euSign = this.euSign;

    await waitLibraryInit();

    if (!euSign.IsInitialized()) euSign.Initialize();

    // аккуратнее с DoesNeedSetSettings — некоторые сборки всегда возвращают true
    const needSettings = euSign.DoesNeedSetSettings();
    if (needSettings) {
      const CAs = JSON.parse(fs.readFileSync(this.CAs, 'utf8'));
      let CASettings = null;
      for (const ca of CAs) {
        if (ca.issuerCNs?.some((cn) => cn === this.PKeySettings.CACommonName)) {
          CASettings = ca;
          break;
        }
      }
      this._setSettings(CAs, CASettings);
      this._loadCertificates(this.CACertificates);
    }

    if (!this.pkContext) {
      this._loadCertificates(this.PKeySettings.certificates);
      const pKeyData = new Uint8Array(fs.readFileSync(this.PKeySettings.filePath));
      this.pkContext = euSign.CtxReadPrivateKeyBinary(
        this.context,
        pKeyData,
        this.PKeySettings.password
      );
    }

    // sanity-check констант
    for (const name of ['EU_CERT_KEY_TYPE_DSTU4145', 'EU_KEY_USAGE_KEY_AGREEMENT']) {
      if (typeof globalThis[name] === 'undefined') {
        throw new Error(`Missing crypto constant: ${name}`);
      }
    }
  }

  _setSettings(CAs, CASettings) {
    const euSign = this.euSign;
  
    euSign.SetJavaStringCompliant(true);
    euSign.SetCharset('UTF-8');
  
    // File store
    let settings = euSign.CreateFileStoreSettings();
    settings.SetPath('');
    settings.SetSaveLoadedCerts(false);
    euSign.SetFileStoreSettings(settings);
  
    // OFFLINE режим (ключевое)
    settings = euSign.CreateModeSettings();
    settings.SetOfflineMode(true);            // <-- принудительно офлайн
    euSign.SetModeSettings(settings);
  
    // Прокси (пусто)
    euSign.SetProxySettings(euSign.CreateProxySettings());
  
    // TSP — не ходим за штампами
    settings = euSign.CreateTSPSettings();
    settings.SetGetStamps(false);             // <-- выключено
    euSign.SetTSPSettings(settings);
  
    // OCSP — полностью выкл
    settings = euSign.CreateOCSPSettings();
    settings.SetUseOCSP(false);               // <-- выключено
    settings.SetBeforeStore(false);
    euSign.SetOCSPSettings(settings);
  
    const ocspMode = euSign.CreateOCSPAccessInfoModeSettings();
    ocspMode.SetEnabled(false);               // <-- выкл
    euSign.SetOCSPAccessInfoModeSettings(ocspMode);
  
    // CMP — выкл
    settings = euSign.CreateCMPSettings();
    settings.SetUseCMP(false);                // <-- выключено
    euSign.SetCMPSettings(settings);
  
    // LDAP пустой
    euSign.SetLDAPSettings(euSign.CreateLDAPSettings());
  
    // Контекст
    this.context = euSign.CtxCreate();
  }
  

  _loadCertificates(certsFilePaths) {
    if (!certsFilePaths) return;
    const euSign = this.euSign;
    for (const filePath of certsFilePaths) {
      const data = new Uint8Array(fs.readFileSync(filePath));
      if (filePath.toLowerCase().endsWith('.p7b')) {
        euSign.SaveCertificates(data);
      } else {
        euSign.SaveCertificate(data);
      }
    }
  }

  async getEnvelopCertificate() {
    await this._initialize();
    const envCert = this.euSign.CtxGetOwnCertificate(
      this.pkContext,
      EU_CERT_KEY_TYPE_DSTU4145,
      EU_KEY_USAGE_KEY_AGREEMENT
    );
    return this.euSign.Base64Encode(envCert.GetData());
  }

  async developData(envData) {
    await this._initialize();
    const senderInfo = this.euSign.CtxDevelopData(this.pkContext, envData, null);
    senderInfo.data = this.euSign.ArrayToString(senderInfo.GetData());
    return senderInfo;
  }

  async decrypt(encryptedBase64) {
    const buf = Buffer.from(encryptedBase64, 'base64');
    const info = await this.developData(buf);
    try {
      return JSON.parse(info.data);
    } catch {
      return info.data;
    }
  }
}

const g_euSign = new EndUserSignModule(
    CAS,
    CA_CERTIFICATES,
    PKEY_PARAMETERS
  );
  export default g_euSign;
