
import html
import bcrypt

# Function to sanitise text manually
def replace_characters(input_string: str) -> str:
    to_replace = ["<", ">", ";"]
    replacements = ["%3C", "%3E", "%3B"]
    char_list = list(input_string)
    for i in range(len(char_list)):
        if char_list[i] in to_replace:
            index = to_replace.index(char_list[i])
            char_list[i] = replacements[index]
    # Join the list back into a string and return it
    return "".join(char_list)


# Function to sanitise text using a library
def make_web_safe(string: str) -> str:
    return html.escape(string)


# A simple function to check a name is valid
def validate_name(name: str) -> bool:
    # Check if the name is valid (only alphabets allowed).
    if not name.isalpha():
        return False
    return True


# A simple function to check a number is valid
def validate_number(number: str) -> bool:
    # Check if the name is valid (only alphabets allowed).
    if number.isalpha():
        return False
    return True


# Function to salt and hash a password using bcrypt
# Returns a UTF-8 decoded string suitable for storage in a database.
def salt_and_hash(password: str) -> str:
    if not issubclass(type(password), str):
        raise TypeError("Expected a string")
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")
