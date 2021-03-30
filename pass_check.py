import requests
import hashlib
import re


def request_pwned_api_data(query_chars):
    url = f"https://api.pwnedpasswords.com/range/{query_chars}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Status code {res.status_code} received, " +
                           "check the API\'s url and the query\'s " +
                           "functionality.")
    return res


# Pwned API requires the first 5 chars of a SHA-1 hash in the uppercase
# hexadecimal format of a UTF-8 encoded password
def pwned_api_password_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    sha1p_first5, sha1p_suffix = sha1password[:5], sha1password[5:]
    response = request_pwned_api_data(sha1p_first5)
    return hash_search(response, sha1p_suffix)


# The API returns suffixes of all password hashes in its database
# that begin with the given prefix (the first 5 chars)
def hash_search(api_response, hash_to_check):
    hash_count_generator = (line.split(":") for line in api_response.text.splitlines())
    for hash, count in hash_count_generator:
        if hash == hash_to_check:
            return count


def gather_passwords():
    with open("./passwords.txt", mode="r", encoding="utf-8") as my_file:
        password_list = []
        while True:
            file_line = my_file.readline()
            if file_line == "":
                return password_list
            else:
                match = re.search("(.*[^\n\r]$)", file_line)
                try:
                    password_list.append(match.group(0))
                except AttributeError:
                    continue  # for lines containing only a newline


def main():
    password_list = gather_passwords()
    if password_list:
        for password in password_list:
            breach_count = pwned_api_password_check(password)
            if breach_count:
                print(f"The password \"{password}\" has been exposed " +
                      f"{breach_count} times in data breaches " +
                      "based on the records from the Pwned Passwords API. " +
                      "You should change it.")
            else:
                print(f"Congratulations, the password \"{password}\" " +
                      "hasn't been pwned.")
        with open("./passwords.txt", mode="w", encoding="utf-8") as my_file:
            print("Contents of the passwords.txt file have been deleted " +
                  "for you. You're welcome. " +
                  "Don't forget to clear your command line screen!")
    else:
        print("Fill passwords.txt with passwords you would like to check " +
              "for data breaches. Use one password per line.")


if __name__ == "__main__":
    main()
