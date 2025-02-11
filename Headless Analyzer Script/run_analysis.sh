#!/bin/bash
# Configure these variables according to your environment.
GHIDRA_INSTALL="/opt/ghidra"
PROJECT_PATH="/home/kali/Desktop"
PROJECT_NAME="DLLAnalysis"
SCRIPT_PATH="/home/kali/ghidra_scripts"
SCRIPT_NAME="extractnimport2csv.py"
INPUT_DIR="/home/kali/Desktop/Chapter_12L"
OUTPUT_CSV="detection_results.csv"
LOG_FILE="ghidra_analysis.log"

# Ensure the Ghidra project directory exists
mkdir -p "${PROJECT_PATH}/${PROJECT_NAME}.rep"

# Initialize or overwrite the CSV file with a header row
echo "Filename,Detection" > "${OUTPUT_CSV}"

# Clear previous log file or create a new one
echo "" > "${LOG_FILE}"

# Iterate over each .exe file in the input directory
for f in "${INPUT_DIR}"/*.exe; do
    # Check if .exe files exist in the directory
    if [ ! -e "${f}" ]; then
        echo "No .exe files found in ${INPUT_DIR}."
        break
    fi

    # Run Ghidra in headless mode to analyze the executable and run the script
    "${GHIDRA_INSTALL}/support/analyzeHeadless" \
        "${PROJECT_PATH}" \
        "${PROJECT_NAME}" \
        -import "${f}" \
        -overwrite \
        -scriptPath "${SCRIPT_PATH}" \
        -postScript "${SCRIPT_NAME}" \
        -scriptLog "${LOG_FILE}" \
        >> "${OUTPUT_CSV}" 2>&1

    # Optionally, remove the imported program from the project to keep it clean
    rm -f "${PROJECT_PATH}/${PROJECT_NAME}.rep/ghidra.program.database/${f##*/}.g3db"
done

echo "Analysis complete. Results saved to ${OUTPUT_CSV}."
echo "Logs saved to ${LOG_FILE}."
