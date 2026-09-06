"use strict";
const output = document.querySelector("#result");
for (const button of document.querySelectorAll("button[data-action]")) {
  button.addEventListener("click", async () => {
    const buttons = document.querySelectorAll("button");
    for (const item of buttons) item.disabled = true;
    try {
      const action = button.dataset.action;
      const body = action === "attenuate"
        ? {file: document.querySelector("#file").value, seconds: Number(document.querySelector("#seconds").value)}
        : {};
      const response = await fetch(`/action/${action}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
      output.textContent = JSON.stringify(await response.json(), null, 2);
    } catch {
      output.textContent = "The operation could not be completed. Check that all three services are available.";
    } finally {
      for (const item of buttons) item.disabled = false;
    }
  });
}
