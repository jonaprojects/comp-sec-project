const form = document.getElementById("register-form");

form.addEventListener("submit", (event) => {
  const username = document.getElementById("username").value;
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  if (
    !isValidUsername(username) ||
    !isValidEmail(email) ||
    !isValidPassword(password)
  ) {
    // TODO: improve this to help the client fix it (add warnings and messages)
    event.preventDefault();
    alert("Invalid registeration details!");
  }
});
