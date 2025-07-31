import { Message } from "./types";

const mockMessages: Message[] = [
  {
    role: "user",
    content: "Hello, how are you?",
  },
  {
    role: "assistant",
    content: "I am good, thank you!",
    reasoning: "Reasoning example",
  },
  {
    role: "user",
    content:
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
  },
  {
    role: "assistant",
    content:
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
    reasoning:
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
  },
  {
    role: "user",
    content: "Can you show me an example of a table?",
  },
  {
    role: "assistant",
    content: `Here's an example of a table:

| Name | Age | City | Email | Phone | Address | Company | Position | Salary | Department |
|------|-----|------|-------|-------|---------|---------|----------|--------|------------|
| John | 25  | NYC  | john@email.com | 555-0101 | 123 Main St | Tech Corp | Developer | 75000 | Engineering |
| Jane | 30  | LA   | jane@email.com | 555-0102 | 456 Oak Ave | Design Inc | Designer | 80000 | Creative |
| Bob  | 35  | SF   | bob@email.com | 555-0103 | 789 Pine Rd | Data Co | Analyst | 85000 | Analytics |
| Alice | 28  | Chicago | alice@email.com | 555-0104 | 321 Elm St | Marketing Pro | Manager | 90000 | Marketing |
| Charlie | 32  | Boston | charlie@email.com | 555-0105 | 654 Maple Dr | Finance Ltd | Accountant | 70000 | Finance |
| Diana | 29  | Seattle | diana@email.com | 555-0106 | 987 Cedar Ln | HR Solutions | Specialist | 65000 | Human Resources |
| Edward | 31  | Austin | edward@email.com | 555-0107 | 147 Birch Way | Sales Force | Representative | 72000 | Sales |
| Fiona | 27  | Denver | fiona@email.com | 555-0108 | 258 Spruce Ct | Legal Partners | Paralegal | 68000 | Legal |
| George | 33  | Miami | george@email.com | 555-0109 | 369 Willow Pl | Research Lab | Scientist | 95000 | Research |
| Helen | 26  | Portland | helen@email.com | 555-0110 | 741 Aspen Blvd | Support Team | Coordinator | 60000 | Customer Service |

This is a simple table with three columns: Name, Age, and City. The table shows data for three people with their respective ages and cities.

## code block

\`\`\`
cd ..
python -m pip install pandas[plotting]
\`\`\`

# H1 title

**bold text**

_italic text_

~~strikethrough text~~

## H2 title

### H3 title

#### H4 title

##### H5 title

--------------


## check list

- [X] install pandas
- [ ] install matplotlib
- [ ] install seaborn

# My List

- First bullet point
  - First sub-item
  - Second sub-item
    - First sub-sub-item
    - Second sub-sub-item
- Second bullet point
  a. First sub-item
  b. Second sub-item
- Third bullet point

## Numbered List

1. First item
   - First sub-item
   - Second sub-item
2. Second item
   1. First sub-item
   2. Second sub-item
3. Third item
4. Fourth item
`,
  },
];

export { mockMessages };
