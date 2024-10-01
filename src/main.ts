import { MsPkceFlowJs } from "./MsPkceFlowJs.ts";

async function main() {
  debugger

  // some tricks to make it work on github pages too
  let redirect_uri = "http://localhost:8080";
  if (location.host === "vegarringdal.github.io") {
    redirect_uri = "https://vegarringdal.github.io/MsPkceFlowJs/";
  }

  //create/configure flow
  const msPkceFlowJs = new MsPkceFlowJs(
    {
      // config
      // dummy app registration
      client_id: "2bca3844-d481-4fd0-a2fe-53a237ec28ec",
      tenant_id: "0bfdc7b6-077d-4379-9617-c56c6453235b",
      scope: "api://2bca3844-d481-4fd0-a2fe-53a237ec28ec/api",
      redirect_uri,
    }
  );

  const app = document.getElementById("app");
  if (!app) {
    console.error("Unable to find app element");
    return;
  }

  // init msal flow
  const tokenResult = await msPkceFlowJs.init();
  if (tokenResult.state === "error") {
    app.textContent = tokenResult.error.msg;
    return;
  }

  // just to show what we have
  const accessTokenString = msPkceFlowJs.getAccessToken();
  const newToken = await msPkceFlowJs.updateToken();


  console.log("tokenResult:", tokenResult);
  console.log("accessTokenString:", accessTokenString);
  console.log("newToken:", newToken);
  
  

  app.textContent =
    (tokenResult.data.access_token_tokenDecoded.name || "?? ") + ", see console for more data";
}

main();
