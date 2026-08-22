// CapMonster Cloud integration — supports 22 CAPTCHA types via unified detector
// and dispatcher. Disabled by default. Enable with CAPMONSTER_ENABLED=true + key.
//
// Docs: https://docs.capmonster.cloud/en/docs/captchas/
//
// Commit history:
//   v1 — Turnstile only
//   v2 — added reCAPTCHA v2 + hCaptcha (hCaptcha disabled by CapMonster account)
//   v3 — added: Cloudflare Challenge, reCAPTCHA v3, reCAPTCHA v2 Enterprise,
//        reCAPTCHA v3 Enterprise, GeeTest, DataDome, Tencent, Amazon WAF,
//        FaucetPay (Basilisk), Imperva, Prosopo, Text CAPTCHA, Yidun,
//        MTCaptcha, Altcha, FunCaptcha, TSPD, Hunt, Alibaba, Friendly.

import type { Page } from 'playwright';

const CREATE_TASK_URL = 'https://api.capmonster.cloud/createTask';
const GET_TASK_RESULT_URL = 'https://api.capmonster.cloud/getTaskResult';

const CAPMONSTER_API_KEY = process.env.CAPMONSTER_API_KEY || '';
const CAPMONSTER_TIMEOUT_MS = parseInt(
  process.env.CAPMONSTER_TIMEOUT_MS || '60000',
  10,
);
const CAPMONSTER_POLL_INTERVAL_MS = parseInt(
  process.env.CAPMONSTER_POLL_INTERVAL_MS || '2000',
  10,
);
const CAPMONSTER_ENABLED =
  (process.env.CAPMONSTER_ENABLED || 'true').toLowerCase() === 'true';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type CaptchaType =
  | 'turnstile'
  | 'cf-challenge'
  | 'recaptcha-v2'
  | 'recaptcha-v3'
  | 'recaptcha-v2-enterprise'
  | 'recaptcha-v3-enterprise'
  | 'geetest'
  | 'datadome'
  | 'tencent'
  | 'amazon-waf'
  | 'faucetpay'
  | 'imperva'
  | 'prosopo'
  | 'text-captcha'
  | 'yidun'
  | 'mtcaptcha'
  | 'altcha'
  | 'funcaptcha'
  | 'tspd'
  | 'hunt'
  | 'alibaba'
  | 'friendly';

export interface CaptchaWidgetData {
  type: CaptchaType;
  sitekey: string;
  // Generic
  action?: string;
  cData?: string;
  // reCAPTCHA v3 / Enterprise
  pageAction?: string;
  minScore?: number;
  isEnterprise?: boolean;
  enterprisePayload?: Record<string, unknown>;
  apiDomain?: string;
  // GeeTest
  gt?: string;
  challenge?: string;
  version?: number;
  geetestApiServerSubdomain?: string;
  // DataDome
  captchaUrl?: string;
  datadomeCookie?: string;
  // Tencent
  aid?: string;
  tcaptchaUrl?: string;
  // Amazon WAF
  apiKey?: string;
  captchaScript?: string;
  challengeScript?: string;
  context?: string;
  iv?: string;
  // Imperva
  incapsulaScriptUrl?: string;
  incapsulaCookies?: string;
  reese84UrlEndpoint?: string;
  // Prosopo
  // (uses sitekey directly)
  // Yidun
  yidunGetLib?: string;
  yidunApiServerSubdomain?: string;
  // MTCaptcha
  pageActionMTCaptcha?: string;
  isInvisible?: boolean;
  // Altcha
  challengeAltcha?: string;
  iterations?: string;
  salt?: string;
  signature?: string;
  // FunCaptcha
  websitePublicKey?: string;
  funcaptchaApiJSSubdomain?: string;
  blob?: string;
  // TSPD
  tspdCookie?: string;
  htmlPageBase64?: string;
  // Hunt
  apiGetLib?: string;
  data?: string;
  widgetUrl?: string;
  // Alibaba
  sceneId?: string;
  prefix?: string;
  // Friendly
  friendlyApiGetLib?: string;
  // Generic extras
  [key: string]: unknown;
}

interface CreateTaskResponse {
  errorId: number;
  errorCode?: string;
  errorDescription?: string;
  taskId?: number;
}

interface GetTaskResultResponse {
  errorId: number;
  errorCode?: string;
  errorDescription?: string;
  status?: 'processing' | 'ready';
  solution?: {
    token?: string;
    gRecaptchaResponse?: string;
    challenge?: string;
    validate?: string;
    seccode?: string;
    data?: Record<string, string> | string;
    cookies?: Record<string, string>;
    userAgent?: string;
    domains?: Record<string, { cookies?: Record<string, string> }>;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection — runs in browser context via page.evaluate
// ─────────────────────────────────────────────────────────────────────────────

async function detectAnyCaptcha(page: Page): Promise<CaptchaWidgetData | null> {
  return page.evaluate(() => {
    type Result = CaptchaWidgetData | null;

    // ─── Cloudflare Turnstile ────────────────────────────────────
    const ts = document.querySelector<HTMLDivElement>('.cf-turnstile');
    if (ts && ts.dataset.sitekey) {
      return {
        type: 'turnstile',
        sitekey: ts.dataset.sitekey,
        action: ts.dataset.action,
        cData: ts.dataset.cdata,
      } as Result;
    }
    const tsFrame = document.querySelector<HTMLIFrameElement>(
      'iframe[src*="challenges.cloudflare.com"]',
    );
    if (tsFrame) {
      const m = tsFrame.src.match(/sitekey=([0-9a-fx]+)/i);
      if (m) return { type: 'turnstile', sitekey: m[1] } as Result;
    }

    // ─── Cloudflare Challenge ────────────────────────────────────
    if (document.querySelector('#challenge-form')) {
      const ts2 = document.querySelector<HTMLDivElement>('.cf-turnstile');
      if (ts2 && ts2.dataset.sitekey) {
        return {
          type: 'cf-challenge',
          sitekey: ts2.dataset.sitekey,
          action: ts2.dataset.action,
          cData: ts2.dataset.cdata,
        } as Result;
      }
    }

    // ─── reCAPTCHA v2 ────────────────────────────────────────────
    const grec = document.querySelector<HTMLDivElement>('.g-recaptcha');
    if (grec && grec.dataset.sitekey) {
      const isInvisible = grec.dataset.size === 'invisible';
      return {
        type: 'recaptcha-v2',
        sitekey: grec.dataset.sitekey,
        ...(isInvisible && { isInvisible: true }),
      } as Result;
    }

    // ─── reCAPTCHA v3 ────────────────────────────────────────────
    const grecV3 = document.querySelector<HTMLScriptElement>(
      'script[src*="recaptcha/api.js"]',
    );
    if (grecV3) {
      // Look for the explicit render call to extract action.
      // grecaptcha.render(sitekey, {action: 'login'}) is the pattern.
      const renderRegex =
        /grecaptcha\.render\(\s*['"]([^'"]+)['"]\s*,\s*\{[^}]*action\s*:\s*['"]([^'"]+)['"]/i;
      const html = document.documentElement.innerHTML;
      const m = html.match(renderRegex);
      if (m) {
        return {
          type: 'recaptcha-v3',
          sitekey: m[1],
          pageAction: m[2],
        } as Result;
      }
      const urlRender = grecV3.src.match(/[?&]render=([^&]+)/);
      if (urlRender) {
        return { type: 'recaptcha-v3', sitekey: urlRender[1] } as Result;
      }
    }

    // ─── reCAPTCHA Enterprise (v2 or v3) ────────────────────────
    const grecEnt = document.querySelector<HTMLScriptElement>(
      'script[src*="recaptcha/enterprise.js"]',
    );
    if (grecEnt) {
      const m = grecEnt.src.match(/[?&]render=([^&]+)/);
      if (m) {
        return { type: 'recaptcha-v3-enterprise', sitekey: m[1] } as Result;
      }
    }

    // ─── FunCaptcha (Arkose Labs) ────────────────────────────────
    const fc = document.querySelector<HTMLDivElement>('#FunCaptcha, [data-rc-f]');
    if (fc) {
      const fcInput = document.querySelector<HTMLInputElement>('#FunCaptcha-Token, [name="fc-token"]');
      if (fcInput && fcInput.value) {
        const m = fcInput.value.match(/pk=([^|]+)/);
        const surl = fcInput.value.match(/surl=([^|]+)/);
        if (m) {
          return {
            type: 'funcaptcha',
            sitekey: m[1],
            websitePublicKey: m[1],
            ...(surl && { funcaptchaApiJSSubdomain: decodeURIComponent(surl[1]) }),
          } as Result;
        }
      }
    }

    // ─── MTCaptcha ──────────────────────────────────────────────
    const mt = document.querySelector<HTMLDivElement>('.mtcaptcha');
    if (mt && mt.dataset.sitekey) {
      return {
        type: 'mtcaptcha',
        sitekey: mt.dataset.sitekey,
        pageActionMTCaptcha: mt.dataset.action,
      } as Result;
    }

    return null;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// CapMonster API client
// ─────────────────────────────────────────────────────────────────────────────

async function createTask(
  url: string,
  widget: CaptchaWidgetData,
  userAgent: string,
): Promise<number> {
  const taskBody = (() => {
    const baseUA = userAgent;
    const baseProxy: Record<string, unknown> = {
      proxyType: 'http',
      proxyAddress: '127.0.0.1',
      proxyPort: 0,
    };

    switch (widget.type) {
      // ─── Turnstile ─────────────────────────────────────────────
      case 'turnstile':
        return {
          type: 'TurnstileTaskProxyless',
          websiteURL: url,
          websiteKey: widget.sitekey,
          ...(widget.action && { pageAction: widget.action }),
          ...(widget.cData && { data: widget.cData }),
          userAgent: baseUA,
        };

      // ─── Cloudflare Challenge (token variant) ────────────────
      case 'cf-challenge':
        return {
          type: 'TurnstileTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          cloudflareTaskType: 'token',
          pageAction: widget.action || 'managed',
          pageData: widget.cData || '',
          data: widget.cData || '',
          userAgent: baseUA,
        };

      // ─── reCAPTCHA v2 ──────────────────────────────────────────
      case 'recaptcha-v2':
        return {
          type: 'RecaptchaV2TaskProxyless',
          websiteURL: url,
          websiteKey: widget.sitekey,
          ...(widget.isInvisible && { isInvisible: true }),
          userAgent: baseUA,
        };

      // ─── reCAPTCHA v3 ──────────────────────────────────────────
      case 'recaptcha-v3':
        return {
          type: 'RecaptchaV3TaskProxyless',
          websiteURL: url,
          websiteKey: widget.sitekey,
          minScore: widget.minScore || 0.7,
          pageAction: widget.pageAction || 'verify',
          userAgent: baseUA,
        };

      // ─── reCAPTCHA v2 Enterprise ──────────────────────────────
      case 'recaptcha-v2-enterprise':
        return {
          type: 'RecaptchaV2EnterpriseTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          ...(widget.enterprisePayload && {
            enterprisePayload: widget.enterprisePayload,
          }),
          userAgent: baseUA,
        };

      // ─── reCAPTCHA v3 Enterprise ──────────────────────────────
      case 'recaptcha-v3-enterprise':
        return {
          type: 'RecaptchaV3EnterpriseTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          minScore: widget.minScore || 0.7,
          pageAction: widget.pageAction || 'verify',
          userAgent: baseUA,
        };

      // ─── GeeTest v3/v4 ────────────────────────────────────────
      case 'geetest':
        return {
          type: 'GeeTestTask',
          websiteURL: url,
          gt: widget.gt || widget.sitekey,
          ...(widget.version === 3 && widget.challenge && { challenge: widget.challenge }),
          version: widget.version || 3,
          ...(widget.geetestApiServerSubdomain && {
            geetestApiServerSubdomain: widget.geetestApiServerSubdomain,
          }),
          userAgent: baseUA,
        };

      // ─── DataDome ─────────────────────────────────────────────
      case 'datadome':
        return {
          type: 'CustomTask',
          class: 'DataDome',
          websiteURL: url,
          userAgent: baseUA,
          metadata: {
            captchaUrl: widget.captchaUrl || '',
            datadomeCookie: widget.datadomeCookie || '',
            datadomeVersion: 'new',
          },
          ...baseProxy,
        };

      // ─── Tencent (TenDI) ──────────────────────────────────────
      case 'tencent':
        return {
          type: 'CustomTask',
          class: 'TenDI',
          websiteURL: url,
          websiteKey: widget.aid || widget.sitekey,
          userAgent: baseUA,
          metadata: {
            ...(widget.tcaptchaUrl && { captchaUrl: widget.tcaptchaUrl }),
          },
        };

      // ─── Amazon WAF ────────────────────────────────────────────
      case 'amazon-waf':
        return {
          type: 'AmazonTask',
          websiteURL: url,
          websiteKey: widget.apiKey || widget.sitekey,
          userAgent: baseUA,
          ...(widget.captchaScript && { captchaScript: widget.captchaScript }),
          ...(widget.challengeScript && { challengeScript: widget.challengeScript }),
          ...(widget.context && { context: widget.context }),
          ...(widget.iv && { iv: widget.iv }),
          cookieSolution: true,
        };

      // ─── FaucetPay (Basilisk) ─────────────────────────────────
      case 'faucetpay':
        return {
          type: 'CustomTask',
          class: 'Basilisk',
          websiteURL: url,
          websiteKey: widget.sitekey,
          userAgent: baseUA,
        };

      // ─── Imperva (Incapsula) ────────────────────────────────
      case 'imperva':
        return {
          type: 'CustomTask',
          class: 'Imperva',
          websiteURL: url,
          userAgent: baseUA,
          metadata: {
            incapsulaScriptUrl: widget.incapsulaScriptUrl || '',
            incapsulaCookies: widget.incapsulaCookies || '',
            ...(widget.reese84UrlEndpoint && {
              reese84UrlEndpoint: widget.reese84UrlEndpoint,
            }),
          },
          ...baseProxy,
        };

      // ─── Prosopo ──────────────────────────────────────────────
      case 'prosopo':
        return {
          type: 'ProsopoTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          userAgent: baseUA,
        };

      // ─── Text CAPTCHA (image-to-text) ─────────────────────────
      // Requires imageBase64 to be passed via widget.imageBase64
      case 'text-captcha':
        return {
          type: 'ImageToTextTask',
          body: (widget as unknown as { imageBase64?: string }).imageBase64 || '',
        };

      // ─── Yidun ───────────────────────────────────────────────
      case 'yidun':
        return {
          type: 'YidunTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          userAgent: baseUA,
          ...(widget.yidunGetLib && { yidunGetLib: widget.yidunGetLib }),
          ...(widget.yidunApiServerSubdomain && {
            yidunApiServerSubdomain: widget.yidunApiServerSubdomain,
          }),
          ...(widget.challenge && { challenge: widget.challenge }),
          ...(widget.data && { hcg: widget.data }),
        };

      // ─── MTCaptcha ────────────────────────────────────────────
      case 'mtcaptcha':
        return {
          type: 'MTCaptchaTask',
          websiteURL: url,
          websiteKey: widget.sitekey,
          ...(widget.pageActionMTCaptcha && {
            pageAction: widget.pageActionMTCaptcha,
          }),
          ...(widget.isInvisible !== undefined && {
            isInvisible: widget.isInvisible,
          }),
          userAgent: baseUA,
        };

      // ─── Altcha ───────────────────────────────────────────────
      case 'altcha':
        return {
          type: 'CustomTask',
          class: 'altcha',
          websiteURL: url,
          websiteKey: '',
          userAgent: baseUA,
          metadata: {
            challenge: widget.challengeAltcha || '',
            iterations: widget.iterations || '5000',
            salt: widget.salt || '',
            signature: widget.signature || '',
          },
        };

      // ─── FunCaptcha (Arkose Labs) ────────────────────────────────
      case 'funcaptcha':
        return {
          type: 'FunCaptchaTask',
          websiteURL: url,
          websitePublicKey: widget.websitePublicKey || widget.sitekey,
          ...(widget.funcaptchaApiJSSubdomain && {
            funcaptchaApiJSSubdomain: widget.funcaptchaApiJSSubdomain,
          }),
          ...(widget.blob && { data: JSON.stringify({ blob: widget.blob }) }),
          userAgent: baseUA,
        };

      // ─── TSPD ─────────────────────────────────────────────────
      case 'tspd':
        return {
          type: 'CustomTask',
          class: 'tspd',
          websiteURL: url,
          userAgent: baseUA,
          metadata: {
            tspdCookie: widget.tspdCookie || '',
            htmlPageBase64: widget.htmlPageBase64 || '',
          },
          ...baseProxy,
        };

      // ─── Hunt ─────────────────────────────────────────────────
      case 'hunt':
        return {
          type: 'CustomTask',
          class: 'HUNT',
          websiteURL: url,
          userAgent: baseUA,
          metadata: {
            apiGetLib: widget.apiGetLib || '',
            ...(widget.data && { data: widget.data }),
            ...(widget.widgetUrl && { widgetUrl: widget.widgetUrl }),
          },
          ...baseProxy,
        };

      // ─── Alibaba ──────────────────────────────────────────────
      case 'alibaba':
        return {
          type: 'CustomTask',
          class: 'alibaba',
          websiteURL: url,
          userAgent: baseUA,
          metadata: {
            sceneId: widget.sceneId || widget.sitekey,
            prefix: widget.prefix || '',
          },
        };

      // ─── Friendly ─────────────────────────────────────────────
      case 'friendly':
        return {
          type: 'CustomTask',
          class: 'friendly',
          websiteURL: url,
          websiteKey: widget.sitekey,
          userAgent: baseUA,
          metadata: {
            apiGetLib: widget.friendlyApiGetLib || widget.apiGetLib || '',
          },
        };

      default:
        throw new Error(`Unsupported captcha type: ${(widget as CaptchaWidgetData).type}`);
    }
  })();

  const res = await fetch(CREATE_TASK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientKey: CAPMONSTER_API_KEY, task: taskBody }),
  });

  if (!res.ok) {
    throw new Error(
      `CapMonster createTask HTTP error: ${res.status} ${res.statusText}`,
    );
  }

  const data = (await res.json()) as CreateTaskResponse;
  if (data.errorId !== 0) {
    throw new Error(
      `CapMonster createTask error: ${data.errorCode} - ${data.errorDescription}`,
    );
  }
  if (!data.taskId) {
    throw new Error('CapMonster returned no taskId');
  }
  return data.taskId;
}

async function waitForResult(taskId: number): Promise<GetTaskResultResponse['solution']> {
  const start = Date.now();
  while (Date.now() - start < CAPMONSTER_TIMEOUT_MS) {
    const res = await fetch(GET_TASK_RESULT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientKey: CAPMONSTER_API_KEY, taskId }),
    });
    if (!res.ok) {
      throw new Error(
        `CapMonster getTaskResult HTTP error: ${res.status} ${res.statusText}`,
      );
    }
    const data = (await res.json()) as GetTaskResultResponse;
    if (data.errorId !== 0) {
      throw new Error(
        `CapMonster getTaskResult error: ${data.errorCode} - ${data.errorDescription}`,
      );
    }
    if (data.status === 'ready' && data.solution) {
      return data.solution;
    }
    await new Promise((r) => setTimeout(r, CAPMONSTER_POLL_INTERVAL_MS));
  }
  throw new Error(
    `CapMonster timed out after ${CAPMONSTER_TIMEOUT_MS}ms (taskId=${taskId})`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Token injection — sets the appropriate input + fires any registered callback
// ─────────────────────────────────────────────────────────────────────────────

async function injectToken(
  page: Page,
  type: CaptchaType,
  solution: NonNullable<GetTaskResultResponse['solution']> | undefined,
): Promise<void> {
  await page.evaluate(
    ({ tokenType, sol }) => {
      const INPUT_SELECTORS: Record<string, string> = {
        'turnstile': 'input[name="cf-turnstile-response"]',
        'cf-challenge': 'input[name="cf-turnstile-response"]',
        'recaptcha-v2':
          'textarea[name="g-recaptcha-response"], #g-recaptcha-response',
        'recaptcha-v3':
          'textarea[name="g-recaptcha-response"], #g-recaptcha-response',
        'recaptcha-v2-enterprise':
          'textarea[name="g-recaptcha-response"], #g-recaptcha-response',
        'recaptcha-v3-enterprise':
          'textarea[name="g-recaptcha-response"], #g-recaptcha-response',
        geetest: 'input[name="geetest_validate"], #geetest_validate',
        mtcaptcha: 'input[name="mtcaptcha-verifiedtoken"]',
        funcaptcha: 'input[name="fc-token"], #verification-token, [name="FunCaptcha-Token"]',
        prosopo: 'input[name="prosopo-verifiedtoken"], [data-prosopo-token]',
      };

      const tokenStr = String(
        (sol as { token?: string }).token ??
          (sol as { gRecaptchaResponse?: string }).gRecaptchaResponse ??
          (sol as { data?: unknown }).data ??
          '',
      );

      // Standard hidden input / textarea injection
      const input = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(
        INPUT_SELECTORS[tokenType],
      );
      if (input) input.value = tokenStr;

      // Generic event so page-side JS can react
      document.dispatchEvent(
        new CustomEvent('captcha-solved', { detail: { type: tokenType, solution: sol } }),
      );

      // Common global callbacks
      const w = window as unknown as Record<string, unknown>;
      const cbNames: Record<string, string[]> = {
        turnstile: ['turnstileCallback'],
        'cf-challenge': ['turnstileCallback'],
        'recaptcha-v2': ['___grecaptcha_cfg.clients[0].K.K.callback'],
        'recaptcha-v3': ['___grecaptcha_cfg.clients[0].K.K.callback'],
        'recaptcha-v2-enterprise': ['___grecaptcha_cfg.clients[0].K.K.callback'],
        'recaptcha-v3-enterprise': ['___grecaptcha_cfg.clients[0].K.K.callback'],
        mtcaptcha: ['mtcaptchaVerifiedCallback'],
        funcaptcha: ['onFunCaptchaSuccess'],
      };
      for (const cb of cbNames[tokenType] || []) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fn = (cb.split('.').reduce<any>(
          (acc, k) => (acc ? acc[k] : undefined),
          w,
        ) as ((s: string) => void) | undefined);
        if (typeof fn === 'function') {
          try { fn(tokenStr); } catch { /* noop */ }
        }
      }
    },
    { tokenType: type, sol: solution },
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point — called by api.ts after page.goto()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detects any supported CAPTCHA on the page, solves it via CapMonster, and
 * injects the token. Returns true if a CAPTCHA was found and solved.
 *
 * Disabled by default. Enable with CAPMONSTER_ENABLED=true + CAPMONSTER_API_KEY.
 */
export async function solveCaptchaIfPresent(
  page: Page,
  url: string,
): Promise<boolean> {
  if (!CAPMONSTER_ENABLED || !CAPMONSTER_API_KEY) {
    return false;
  }

  let widget: CaptchaWidgetData | null;
  try {
    widget = await detectAnyCaptcha(page);
  } catch (err) {
    console.error(`[capmonster] detection failed: ${(err as Error).message}`);
    return false;
  }
  if (!widget) {
    return false;
  }

  console.log(
    `[capmonster] ${widget.type} detected (sitekey=${widget.sitekey}), solving...`,
  );

  try {
    const userAgent = await page.evaluate(() => navigator.userAgent);
    const taskId = await createTask(url, widget, userAgent);
    console.log(`[capmonster] task created: ${taskId}, polling...`);
    const solution = await waitForResult(taskId);
    console.log(`[capmonster] ${widget.type} solved`);
    await injectToken(page, widget.type, solution);
    return true;
  } catch (err) {
    console.error(`[capmonster] solve failed: ${(err as Error).message}`);
    return false;
  }
}

// Backward-compat alias.
export const solveTurnstileIfPresent = solveCaptchaIfPresent;
