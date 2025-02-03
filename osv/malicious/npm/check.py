import os
import csv

def check_and_parse_filenames(folder_list):
    current_directory = os.getcwd()  # Get the current working directory
    parsed_files = []

    for folder in folder_list:
        folder_path = os.path.join(current_directory, folder)

        if os.path.isdir(folder_path):  # Check if it's a valid folder
            print(f"Checking folder: {folder_path}")

            # List all files inside the folder
            files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

            if files:
                # Extract filename without extension from each file
                for file in files:
                    file_name = os.path.splitext(file)[0]
                    parsed_files.append({"Folder": folder, "File Name Without Extension": file_name})
                    print(f"Extracted file name: {file_name} from {folder}")

    return parsed_files

def write_to_csv(parsed_files):
    if not parsed_files:
        print("No valid filenames to write to CSV.")
        return

    output_file = "output.csv"
    
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Folder", "File Name Without Extension"])  # CSV Header
        
        for entry in parsed_files:
            writer.writerow([entry["Folder"], entry["File Name Without Extension"]])
    
    print(f"Data written to {output_file}")

# Example list
folders = ["@wongapl/offer-box", "@wongapl/offer-digest", "@wongapl/offer-selector", "@wongapl/offer-ui-tools", "@wongapl/sliders", "abha", "elabasia-mobileapp-react-native-ui", "finfonfon", "gitgotgottten", "herostereo", "is-number-ctf", "isctf11", "isctf16", "isctf17", "isctf2", "isctf3", "isctf4", "isctf5", "jqtools-overlay", "nodejs-paypal-checkout-demo", "offer-ui-tools", "prajwal_kewat-test-package", "react-native-country-picker-modal-modified", "skulldentist", "testingthesand", "tittottit", "ua.unitedforbusiness.frontend", "unitedrabbits", "@infinid-indonesia/ui-kit", "apple-payment", "apple-sdk", "apple-sync", "apple-test", "apple-tests", "apple-tools", "apple-user", "apple-utils", "ar2-common", "aws-genai-llm-chatbot", "awsume", "bazelbuild.vscode-bazel", "bloomr-ts", "blynk-ide", "bookingcom-admin", "bookingcom-connect", "bookingcom-database", "bookingcom-db", "bookingcom-event", "cg-be-package", "cms-vue-boilerplate", "codat", "com.siccity.gltfutility", "external-adapters-js", "files_texteditor", "guests", "html-webpack-plugin-v4", "html-webpack-plugin-v5", "ibm.github.io", "k6-docs", "lib-automotive-call-cdm", "llvm-vs-code-extensions.vscode-clangd", "minikit-monorepo", "pages-proxy", "roro1", "roro2", "roro3", "sahasuhdjdhajdhja", "shader-examples", "spicy-sections", "twilio.github.io", "typespublishercontenthash", "user-switching"]

# Run function
parsed_filenames = check_and_parse_filenames(folders)
write_to_csv(parsed_filenames)