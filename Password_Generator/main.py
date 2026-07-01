import secrets

upper_case =  "QWERTYUIOPASDFGHJKLZXCVBNM"
lower_case = "qwertyuiopasdfghjklzxcvbnm"
special_char = "!@#$%^&*()-=_+"
numbers = "1234567890"

def Password(pass_len):
    part1 = round(pass_len * 30/100)
    part2 = round(pass_len * 20/100)

    char_list = []
    result = ""

    for i in range(part1):
        char_list += secrets.choice(upper_case)
        char_list += secrets.choice(lower_case)
    for i in range(part2):
        char_list += secrets.choice(special_char)
        char_list += secrets.choice(numbers)
    
    secrets.SystemRandom(char_list)
    result = "".join(char_list)
    return result

while True:
    pass_len = int(input("Enter a length for your password: \n"))
    
    print(Password(pass_len))
    print("\n")