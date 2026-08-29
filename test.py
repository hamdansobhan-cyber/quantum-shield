import subprocess

target = input("Enter target: ")

result = subprocess.getoutput(
    f"nmap {target}"
)

lines = result.splitlines()

for line in lines:

    if "/tcp" in line:

        parts = line.split()

        port = parts[0]

        state = parts[1]

        service = parts[2]

        print("PORT:", port)
        print("STATE:", state)
        print("SERVICE:", service)

        print("-------------")