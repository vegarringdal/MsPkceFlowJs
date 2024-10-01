import { MsPkceFlowJs } from "./MsPkceFlowJs.ts";

async function main() {



  
  const msPkceFlowJs = new MsPkceFlowJs(
    {
      // dummy app registration
      client_id: "2bca3844-d481-4fd0-a2fe-53a237ec28ec",
      tenant_id: "0bfdc7b6-077d-4379-9617-c56c6453235b",
      scope: "api://2bca3844-d481-4fd0-a2fe-53a237ec28ec/api",
      redirect_uri: "http://localhost:8080",
    },

    // callback
    // this prob should be events... and user should be able to subscribe...
    (result) => {
      console.log(result);
    }
  );

  msPkceFlowJs.useLog = true;

  // activate
  const tokenResult = await msPkceFlowJs.activate().catch((e) => {
    // something wrong, maybe we should return a object with success or error state ?
    console.error(e);
  });

  const app = document.getElementById("app");

  if (!tokenResult && app) {
    app.textContent = "something wrong, see console";
    return;
  }

  if (tokenResult) {
    const accessTokenString = msPkceFlowJs.getAccessToken();
    const newToken = await msPkceFlowJs.updateToken();

    console.log("tokenResult:", tokenResult);
    console.log("accessTokenString:", accessTokenString);
    console.log("newToken:", newToken);

    if (app) {
      app.textContent =
        tokenResult.access_token_tokenDecoded.name || "who are you?";
    }
  }
}

main();
