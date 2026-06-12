# How to Use VS Code with the Replit File

This guide explains how to set up and use Visual Studio Code (VS Code) to interact with the files from this repository, enabling you to practice Linux commands and navigate the filesystem in your local environment.

---

## Prerequisites

Before you begin, ensure you have the following installed on your computer:

1. [Visual Studio Code (VS Code)](https://code.visualstudio.com/) - A lightweight code editor with built-in terminal support.
2. **Bash Terminal**:
   - For Linux/Mac: Use the built-in terminal.
   - For Windows: Use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) or Git Bash (included with Git).

---

## Steps to Use VS Code with the Files

### 1. Download the Replit File

1. Download the Replit file provided during the workshop.
2. Extract the contents of the file to a folder on your computer.

---

### 2. Open the Files in VS Code

1. Open **Visual Studio Code**.
2. Click **File > Open Folder**.
3. Navigate to the folder where you extracted the Replit file and select it.
4. The file explorer in VS Code will display the folder structure.

---

### 3. Open the Built-in Terminal

1. Open the terminal in VS Code by clicking **Terminal > New Terminal** or pressing `Ctrl + `` (backtick key).
2. Ensure you're in the correct folder (the root of the extracted Replit files):
   ```bash
   pwd
   ```
   The output should match the path to the folder containing the files.

---

### 4. Practice Linux Commands

With the terminal open, you can now practice Linux commands using the files provided in the repository. Here are some examples:

- **List directory contents**:
  ```bash
  ls
  ```
- **Navigate into a folder**:
  ```bash
  cd folder-name
  ```
- **Display the current directory**:
  ```bash
  pwd
  ```
- **View the contents of a file**:
  ```bash
  cat file-name
  ```

---

### 5. Explore and Complete Challenges

Follow the workshop instructions to navigate the file system, manipulate files, and complete the Linux command challenges.

If you encounter any issues, check your terminal setup or reach out for support.

---

## Notes

- For Windows users: If you're not using WSL, consider installing Git Bash or enabling the Linux subsystem for an authentic Bash experience.
- If you're new to Linux commands, don't hesitate to ask questions or review additional resources provided during the workshop.

Happy learning!
