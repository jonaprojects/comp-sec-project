/* 
Client-side validation functions, following the rules defined in config.py.
*/

/*
Auxiliary Method 
*/

function isDigit(c) {
  return c >= "0" && c <= "9";
}

function isLowercase(c) {
  return c >= "a" && c <= "z";
}

function isUppercase(c) {
  return c >= "A" && c <= "Z";
}

function checkCharacters(text) {
  let findings = {
    hasLowercase: false,
    hasUppercase: false,
    hasSpecial: false,
    hasDigit: false,
  };

  for (let i = 0; i < text.length; i++) {
    let c = text[i];

    let isUpper = isUppercase(c);
    let isLower = isLowercase(c);
    let isdigit = isDigit(c);
    let isSpecial = !isUpper && !isLower && !isdigit && c.trim() !== "";

    if (isUpper) {
      findings.hasUppercase = true;
    }
    if (isLower) {
      findings.hasLowercase = true;
    }
    if (isdigit) {
      findings.hasDigit = true;
    }
    if (isSpecial) {
      findings.hasSpecial = true;
    }
  }
  return findings;
}

/* 
Validation Methods
*/

function isValidUsername(username) {
  // Currently we only perform basic validation on usernames.
  return username.length > 0;
}

function isValidEmail(email) {
  /*
  We utilize the same regex from the backend here 
  (in addition to the browser's more 'allowing' one.)
  */
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return email.length > 0 && emailRegex.test(email);
}

function isValidPassword(password) {
  const rules = window.validationRules;

  if (password.length < rules.password_min_length) {
    return false;
  }

  const findings = checkCharacters(password);

  if (rules.password_require_lowercase && !findings.hasLowercase) {
    return false;
  }

  if (rules.password_require_uppercase && !findings.hasUppercase) {
    return false;
  }

  if (rules.password_require_digit && !findings.hasDigit) {
    return false;
  }

  if (rules.password_require_special && !findings.hasSpecial) {
    return false;
  }

  return true;
}
