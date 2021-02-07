import requests
import hashlib
import sys


def request_pwned_api_data(query_chars):
    url = "https://api.pwnedpasswords.com/range/" + str(query_chars)
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Status code {res.status_code} received, " +
                           "check the API\'s url and the query\'s functionality.")
    return res


# Pwned API requires the first 5 chars of a SHA-1 hash in the uppercase hexadecimal format of a UTF-8 encoded password
def pwned_api_password_check(password):
    sha1password = hashlib.sha1(str(password).encode("utf-8")).hexdigest().upper()
    sha1p_first5, sha1p_suffix = sha1password[:5], sha1password[5:]
    response = request_pwned_api_data(sha1p_first5)
    return hash_search(response, sha1p_suffix)


# The API returns suffixes of all password hashes in its database that begin with the given prefix (the first 5 chars)
def hash_search(api_response, hash_to_check):
    hash_count_generator = (line.split(":") for line in api_response.text.splitlines())
    for hash, count in hash_count_generator:
        if hash == hash_to_check:
            return count


def main(args):
    for password in args:
        count = pwned_api_password_check(password)
        if count:
            print(f"The password {password} has been exposed {count} times in data breaches " +
                  "based on the records from the Pwned Passwords API. You should change it.")
        else:
            print(f"Congratulations, the password {password} hasn't been pwned.")
    print("Don't forget to delete your command line history!")


if __name__ == "__main__":
    main(sys.argv[1:])
