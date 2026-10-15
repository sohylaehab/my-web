const form = document.querySelector("#auth-form");
const tabs = [...document.querySelectorAll(".tab-button")];
const message = document.querySelector("#form-message");
const nameField = document.querySelector("#name-field");
const nameInput = document.querySelector("#name");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const passwordHint = document.querySelector("#password-hint");
const submitButton = document.querySelector("#submit-button");
const submitLabel = document.querySelector("#submit-label");
const signedIn = document.querySelector("#signed-in");
const successTitle = document.querySelector("#success-title");
const successMessage = document.querySelector("#success-message");
let mode = "signup";

function showMessage(text, isSuccess = false) {
  message.textContent = text;
  message.classList.toggle("is-success", isSuccess);
}

function setMode(nextMode) {
  mode = nextMode;
  const signingUp = mode === "signup";
  tabs.forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  nameField.hidden = !signingUp;
  nameInput.required = signingUp;
  nameInput.disabled = !signingUp;
  passwordInput.autocomplete = signingUp ? "new-password" : "current-password";
  passwordInput.minLength = signingUp ? 10 : 1;
  passwordInput.placeholder = signingUp ? "Make it a good one" : "Enter your password";
  passwordHint.textContent = signingUp ? "at least 10 characters" : "";
  document.querySelector("#auth-title").textContent = signingUp ? "Create your account" : "Welcome back";
  document.querySelector("#form-kicker").textContent = signingUp ? "YOUR NEXT CHAPTER STARTS HERE" : "YOUR LITTLE CORNER IS WAITING";
  document.querySelector("#form-subtitle").textContent = signingUp
    ? "A fresh start is just a few details away."
    : "Pick up right where you left off.";
  submitLabel.textContent = signingUp ? "Create my account" : "Log in to my space";
  document.querySelector("#terms-note").textContent = signingUp
    ? "By joining, you agree to keep this a kind little corner."
    : "Your space is just for you.";
  showMessage("");
}

tabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

document.querySelector(".password-toggle").addEventListener("click", (event) => {
  const button = event.currentTarget;
  const reveal = passwordInput.type === "password";
  passwordInput.type = reveal ? "text" : "password";
  button.textContent = reveal ? "Hide" : "Show";
  button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
  button.setAttribute("aria-pressed", String(reveal));
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");
  if (!form.reportValidity()) return;

  submitButton.disabled = true;
  submitLabel.textContent = mode === "signup" ? "Making your space..." : "Opening your space...";
  try {
    const response = await fetch(`/api/${mode}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: nameInput.value.trim(),
        email: emailInput.value.trim(),
        password: passwordInput.value,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Something went wrong. Please try again.");
    form.hidden = true;
    document.querySelector(".auth-tabs").hidden = true;
    successTitle.textContent = mode === "login" ? "You’re logged in!" : `Welcome, ${result.name}!`;
    successMessage.textContent = mode === "login"
      ? "You’re logged in successfully. Your little corner is ready."
      : "Your account is ready. Your little corner is all yours.";
    signedIn.hidden = false;
  } catch (error) {
    showMessage(error instanceof TypeError
      ? "Can’t reach the local server. Please start it and try again."
      : error.message);
  } finally {
    submitButton.disabled = false;
    submitLabel.textContent = mode === "signup" ? "Create my account" : "Log in to my space";
  }
});

document.querySelector("#signout-button").addEventListener("click", async () => {
  try {
    const response = await fetch("/api/logout", { method: "POST" });
    if (!response.ok) throw new Error("Could not sign out. Please try again.");
    signedIn.hidden = true;
    document.querySelector(".auth-tabs").hidden = false;
    form.hidden = false;
    form.reset();
    setMode("login");
    showMessage("You’ve been signed out.", true);
  } catch (error) {
    successMessage.textContent = error.message;
  }
});

async function restoreSession() {
  try {
    const response = await fetch("/api/me");
    if (!response.ok) return;
    const user = await response.json();
    form.hidden = true;
    document.querySelector(".auth-tabs").hidden = true;
    signedIn.hidden = false;
    successTitle.textContent = `Welcome back, ${user.name}!`;
    successMessage.textContent = "You’re logged in successfully. Your little corner is ready.";
  } catch (error) {
    showMessage("Could not check your sign-in. Please refresh to try again.");
  }
}

restoreSession();
