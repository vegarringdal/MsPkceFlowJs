/**
 * MsPkceFlowJs
 * more about microsoft pkce flow here:
 * https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
 */
export class MsPkceFlowJs {
  private authConfig: AuthConfig;
  private stateLocalStorageKey = "__key";
  private verifierLocalStorageKey = "__verifier";
  private codeLocalStorageKey = "__code";
  private lasturlLocalStorageKey = "__lastUrl";
  private useOldStateLocalStorageKey = "__useOldState";
  private accountLocalStorageKey = "__account";
  private currentAccount: TokenResult | null = null;
  public useLog = false;
  callback: (result: TokenResult) => void;

  constructor(authConfig: AuthConfig, callback?: (result: TokenResult) => void) {
    this.authConfig = authConfig;
    this.currentAccount = null;
    this.callback = callback || function(){};
  }

  public getAccessToken() {
    return this.currentAccount?.access_token;
  }

  public async updateToken() {
    const token = this.currentAccount?.refresh_token;

    if (token) {
      const [url, form] = this.#generateTokenRefreshUrl(token);
      const response = await fetch(url, { body: form, method: "POST" });

      if (response.ok) {
        const json = await response.json();
        this.saveToken(json);
        return this.currentAccount;
      }
    } else {
      throw "no refresh token available";
    }
  }

  public async activate() {
    const hash = location.hash.replace("#", "");
    let code = new URLSearchParams(hash).get("code");
    let state = new URLSearchParams(hash).get("state");

    const oldState = sessionStorage.getItem(this.stateLocalStorageKey);
    const oldVerifier = sessionStorage.getItem(this.verifierLocalStorageKey);
    const useOldState = sessionStorage.getItem(this.useOldStateLocalStorageKey);

    if (useOldState) {
      // browser reloaded..
      state = oldState;
      code = sessionStorage.getItem(this.codeLocalStorageKey);
    }

    if (code && oldState && oldVerifier && oldState === state) {
      const oldurl = sessionStorage.getItem(this.lasturlLocalStorageKey);
      if (oldurl) {
        sessionStorage.removeItem(this.lasturlLocalStorageKey);
        // need to save this since we will reload browser one more time..
        sessionStorage.setItem(this.useOldStateLocalStorageKey, "TRUE");
        sessionStorage.setItem(this.codeLocalStorageKey, code);

        const urlObj = JSON.parse(oldurl);
        location.href = `${location.origin}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
        return;
      }
      sessionStorage.removeItem(this.useOldStateLocalStorageKey);

      const url = `https://login.microsoftonline.com/${this.authConfig.tenant_id}/oauth2/v2.0/token`;

      const form = new FormData();
      form.append("scope", this.authConfig.scope);
      form.append("code", code);
      form.append("client_id", this.authConfig.client_id);
      form.append("redirect_uri", this.authConfig.redirect_uri);
      form.append("grant_type", "authorization_code");
      form.append("code_verifier", oldVerifier);

      //get token
      const response = await fetch(url, { body: form, method: "POST" });

      //cleanup
      sessionStorage.removeItem(this.verifierLocalStorageKey);
      sessionStorage.removeItem(this.stateLocalStorageKey);

      if (response.ok) {
        const json = await response.json();

        this.saveToken(json);
        await this.reSheduleRefresh();

        return json as TokenResult;
      } else {
        console.error(response.status, response.statusText);
        return null;
      }
    } else {
      if (oldVerifier && oldState) {
        sessionStorage.removeItem(this.verifierLocalStorageKey);
        sessionStorage.removeItem(this.stateLocalStorageKey);
        sessionStorage.removeItem(this.useOldStateLocalStorageKey);

        throw "auth failed";
      } else {
        sessionStorage.setItem(
          this.lasturlLocalStorageKey,
          JSON.stringify({
            pathname: location.pathname,
            search: location.search,
            hash: location.hash,
          })
        );

        const account = sessionStorage.getItem(this.accountLocalStorageKey);
        if (account) {
          // if we have account lets try and get token silently

          this.currentAccount = JSON.parse(account) as TokenResult;

          await this.reSheduleRefresh();

          // might never get here..
          return this.currentAccount;
        } else {
          await this.#loginRedirect();
        }
      }
    }
  }

  private log(msg: string) {
    if (this.useLog) {
      console.log(msg);
    }
  }

  private async reSheduleRefresh() {
    if (!this.currentAccount) {
      await this.#loginRedirect();
      return;
    }

    const expireDate = new Date(this.currentAccount.expire_isoString).getTime();
    const currentDate = new Date().getTime();

    const expireMs = expireDate - currentDate;
    const buffer5Min = 1000 * 60 * 5;
    const expireMsMinusBuffer = expireMs- buffer5Min

    // if expired we want to redirect
    // I prb could improve this, refresh token last 24hours or 90 days, so maybe just refresh if needed
    if (expireMs < 0) {
      await this.#loginRedirect();
      return;
    }

    // if its past our buffer we also want to update
    if (expireMsMinusBuffer < 0) {
      await this.updateToken().catch(async () => {
        await this.#loginRedirect();
        return;
      });
    }

    //callback, since its still valid
    this.callback(this.currentAccount);

    this.log(`scheduled refresh in ${expireMsMinusBuffer / 1000 / 60}`);

    setTimeout(async () => {
      await this.updateToken().catch(async () => {
        // maybe now what we want..
        sessionStorage.setItem(
          this.lasturlLocalStorageKey,
          JSON.stringify({
            pathname: location.pathname,
            search: location.search,
            hash: location.hash,
          })
        );
        await this.#loginRedirect();
        return;
      });

      if (this.currentAccount) {
        this.callback(this.currentAccount);
      }
    }, expireMsMinusBuffer);
  }

  private saveToken(json: any) {
    if (json.access_token) {
      json.access_token_tokenDecoded = this.#parseJwt(json.access_token);
    }

    json.expire_isoString = new Date(
      json.access_token_tokenDecoded?.exp * 1000
    ).toISOString();

    json.expire_localString = new Date(json.expire_isoString);

    this.currentAccount = json;

    sessionStorage.setItem(this.accountLocalStorageKey, JSON.stringify(json));
  }

  async #loginRedirect() {
    const url = await this.#generateLoginUrl();
    window.open(url, "_self");
  }

  #parseJwt(token: string) {
    if (!token) {
      return {};
    }

    const base64Url = token.split(".")[1];
    if (!base64Url) {
      return {};
    }

    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");

    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split("")
        .map(function (c) {
          return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
    );

    return JSON.parse(jsonPayload);
  }

  async #generatePKCE(length = 96) {
    // collected from misc sources/google searches
    const randomNumbers = await crypto.getRandomValues(new Uint8Array(length));

    let randomString = "";
    randomNumbers.forEach((num) => {
      randomString += String.fromCharCode(num);
    });

    // verifier is something we send to MS after we have gotten a code from them
    const verifier = window
      .btoa(randomString)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const numArray = new Uint8Array(verifier.length);

    for (let i = 0; i < verifier.length; i++) {
      numArray[i] = verifier.charCodeAt(i);
    }

    const digest = await crypto.subtle.digest("SHA-256", numArray);

    const digestBase64String = String.fromCharCode.apply(
      null,
      new Uint8Array(digest) as unknown as number[]
    );

    return {
      verifier,
      challenge: window
        .btoa(digestBase64String)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, ""),
    };
  }

  #generateTokenRefreshUrl(token: string) {
    const authUrl = `https://login.microsoftonline.com/${this.authConfig.tenant_id}/oauth2/v2.0/token`;

    const form = new FormData();
    form.append("client_id", this.authConfig.client_id);
    form.append("refresh_token", token);
    form.append("scope", this.authConfig.scope);
    form.append("grant_type", "refresh_token");

    return [authUrl, form] as [string, FormData];
  }

  async #generateLoginUrl() {
    const PKCE = await this.#generatePKCE();
    const state = crypto.randomUUID();

    sessionStorage.setItem(this.verifierLocalStorageKey, PKCE.verifier);
    sessionStorage.setItem(this.stateLocalStorageKey, state);

    const authUrl = `https://login.microsoftonline.com/${this.authConfig.tenant_id}/oauth2/v2.0/authorize`;

    const urlParam = new URLSearchParams();
    urlParam.append("client_id", this.authConfig.client_id);
    urlParam.append("response_type", "code");
    urlParam.append("response_mode", "fragment");
    urlParam.append("scope", this.authConfig.scope);
    urlParam.append("state", state);
    urlParam.append("code_challenge", PKCE.challenge);
    urlParam.append("redirect_uri", this.authConfig.redirect_uri);
    urlParam.append("code_challenge_method", "S256");

    return authUrl + "?" + urlParam.toString();
  }
}

export type AuthConfig = {
  client_id: string;
  tenant_id: string;
  scope: string;
  redirect_uri: string;
};

export type TokenResult = {
  access_token: string;
  expire_isoString: string;
  expire_localString: Date;
  expires_in: number;
  id_token: string;
  access_token_tokenDecoded: {
    aud: string;
    exp: number;
    iat: number;
    iss: string;
    name: string;
    nbf: number;
    oid: string;
    preffered_username: string;
    rh: string;
    roles: string[];
    sub: string;
    tid: string;
    uti: string;
    ver: string;
  };
  refresh_token: string;
  scope: string;
  token_type: string;
};
