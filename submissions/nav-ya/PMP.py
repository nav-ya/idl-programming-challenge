import sys

# PMP permission bits
PMP_R = 0x1  # Read
PMP_W = 0x2  # Write
PMP_X = 0x4  # Execute

# Privilege levels (M = Machine, S = Supervisor, U = User)
PRIVILEGE_LEVELS = {'M': 3, 'S': 1, 'U': 0}

def load_pmp_config(pmp_file):
    pmp_entries = []
    permission_map = {'R': 1, 'W': 2, 'X': 4}  # Permission mapping

    with open(pmp_file, 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue

            base = int(parts[0], 16)  # Base address in hex
            size = int(parts[1], 16)  # Region size in bytes (hexadecimal)

            # Process permissions and map 'R', 'W', 'X' to integer values
            permissions = 0
            for permission in parts[2]:  # Iterate over each permission character (e.g., 'R', 'W', 'X')
                permissions |= permission_map.get(permission, 0)  # Set corresponding bits for permissions

            pmp_entries.append({
                'base': base,
                'size': size,
                'permissions': permissions
            })

    return pmp_entries

def check_pmp_access(pmp_entries, address, operation, privilege_mode):
    # Convert the address from hex string to integer if it's a string
    address = int(address, 16) if isinstance(address, str) else address

    for entry in pmp_entries:
        base_addr = entry['base']
        size = entry['size']
        permissions = entry['permissions']

        # Check if the address is within the PMP entry range
        if base_addr <= address < base_addr + size:
            # Check if the requested operation is allowed based on permissions
            if operation == 'R' and (permissions & 1):
                return True
            elif operation == 'W' and (permissions & 2):
                return True
            elif operation == 'X' and (permissions & 4):
                return True
            else:
                return False
    return False


def main():
    """Main function to process command-line arguments and check PMP access."""
    if len(sys.argv) != 5:
        print("Usage: python pmp_checker.py <pmp_config_file> <address> <privilege_mode> <operation>")
        sys.exit(1)

    pmp_file = sys.argv[1]
    address = int(sys.argv[2], 16)  # Convert address from hex string to integer
    privilege_mode = sys.argv[3]
    operation = sys.argv[4]

    if operation not in ['R', 'W', 'X']:
        print("Error: Invalid operation. Use 'R' (read), 'W' (write), or 'X' (execute).")
        sys.exit(1)

    pmp_entries = load_pmp_config(pmp_file)
    access_allowed = check_pmp_access(pmp_entries, address, operation, privilege_mode)

    if access_allowed:
        print("Access Allowed")
    else:
        print("Access Fault")

if __name__ == "__main__":
    main()
