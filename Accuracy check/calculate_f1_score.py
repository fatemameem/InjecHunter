import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, classification_report
import sys

# File paths
predicted_file = 'filtered.csv'
actual_file = 'actual_labels.csv'
output_filtered_file = 'final_filtered_detection.csv'

# Read the predicted detections
try:
    predicted_df = pd.read_csv(predicted_file)
    print(f"Loaded {len(predicted_df)} records from {predicted_file}.")
except FileNotFoundError:
    print(f"Error: {predicted_file} not found.")
    sys.exit(1)
except pd.errors.EmptyDataError:
    print(f"Error: {predicted_file} is empty.")
    sys.exit(1)

# Read the actual labels
try:
    actual_df = pd.read_csv(actual_file)
    print(f"Loaded {len(actual_df)} records from {actual_file}.")
except FileNotFoundError:
    print(f"Error: {actual_file} not found.")
    sys.exit(1)
except pd.errors.EmptyDataError:
    print(f"Error: {actual_file} is empty.")
    sys.exit(1)

# Ensure 'Filename' columns exist
if 'Filename' not in predicted_df.columns:
    print("Error: 'Filename' column not found in predicted CSV.")
    sys.exit(1)
if 'Filename' not in actual_df.columns:
    print("Error: 'Filename' column not found in actual labels CSV.")
    sys.exit(1)
if 'Detection' not in predicted_df.columns:
    print("Error: 'Detection' column not found in predicted CSV.")
    sys.exit(1)
if 'Actual' not in actual_df.columns:
    print("Error: 'Actual' column not found in actual labels CSV.")
    sys.exit(1)

# Clean whitespace in 'Filename'
predicted_df['Filename'] = predicted_df['Filename'].str.strip()
actual_df['Filename'] = actual_df['Filename'].str.strip()

# Merge the two DataFrames on 'Filename'
merged_df = pd.merge(predicted_df, actual_df, on='Filename', how='inner')

print(f"Merged DataFrame has {len(merged_df)} records.")

if len(merged_df) == 0:
    print("Error: Merged DataFrame is empty. Check if 'Filename' entries match in both CSV files.")
    sys.exit(1)

# Display the merged DataFrame
print("\nMerged DataFrame Preview:")
print(merged_df.head())

# Extract the predicted and actual labels
y_pred = merged_df['Detection']
y_true = merged_df['Actual']

# Check for valid label values
if not set(y_pred.unique()).issubset({0, 1}):
    print("Error: 'Detection' column contains values other than 0 and 1.")
    sys.exit(1)
if not set(y_true.unique()).issubset({0, 1}):
    print("Error: 'Actual' column contains values other than 0 and 1.")
    sys.exit(1)

# Calculate Precision, Recall, and F1 Score with zero_division=0 to suppress warnings
precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)

# Calculate Confusion Matrix
cm = confusion_matrix(y_true, y_pred)
if cm.shape == (2, 2):
    tn, fp, fn, tp = cm.ravel()
    print("\nConfusion Matrix:")
    print(f"True Negatives (TN): {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"True Positives (TP): {tp}")
else:
    print("\nConfusion Matrix shape is not (2,2).")
    print(cm)
    tn = fp = fn = tp = 'Undefined'

# Display the results
print("\nEvaluation Metrics:")
print(f"Precision: {precision:.2f}")
print(f"Recall:    {recall:.2f}")
print(f"F1 Score:  {f1:.2f}")

# Detailed classification report
print("\nClassification Report:")
print(classification_report(y_true, y_pred, zero_division=0))
