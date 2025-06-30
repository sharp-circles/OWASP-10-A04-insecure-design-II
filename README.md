# OWASP-10-A04-insecure-design-II

Extended reviews for OWASP recommended SAST tooling: Aikido, Trivy and Opengrep. Key insights, scope, limitations and custom rule crafting

### Main lessons

**1. Freemium model limitations in SAST**. Shortage of rules and low detection. They are constructing their business models around the idea of giving you a tiny spectrum of their real service. This was discouraging: the community level services for all these tools is really low and far from doing a barely acceptable job.

**2. They shrink everything, not the services themselves, but also the extensibility options** (SonarQube, for example, only allows for custom ruling on paid models). Here we saw some differences among tools: Opengrep, for example, being more open source friendly, allows for extensibility just at the core of its model.

**3. The big sharks in the game, like Veracode, SonarQube, Aikido or Semgrep, offer a great GUI that provides incredible visualization and accessibility**. This is probably one of the best perks they have: everything is centralized, incredibly easy to use and understand, and all of it is wrapped up with a great design work.

**4. Manual extensibility can be good, but does not scale well**: behind the scenes, that's not more than blacklisting. Blacklisting can be good for a few, deterministic results. But what happens when you add some variability or randomness to the ecuation? It simply won't work. Whitelisting is always the choice when it comes to validation. But whitelisting absolutely clashes with free development will, so it’s hardly an applicable concept.

**5. Surfing, reading and checking the subreddits on this topic, opinions seem to be mixed**. There are supporters and detractors remarking highlights and flaws for each of the tools, so it's probably about you checking those by yourself.

### Opengrep scripts and rules

Opengrep works through a CLI that analyzes code based on preexisting rules. You can extend and customize those. Find an example on the rules folder: ```custom.yml``` file. 

First of all, always take a look at the docs, but also at the help command.

```opengrep.exe --help```

It is usually an invaluable source of knowledge and you can quickly get a grasp of basic functionality.

Once that's done, move on with forward movements:

```./opengrep_windows_x86.exe scan --metrics=auto -f ./../rules --sarif-output=sarif.json --verbose ./```

I chose that combination for log granularity and prettified json outputs. Bear in mind you can specify single files or folders for analysis.

#### Output examples

**CLI**

```
┌──────────────┐
│ Scan Summary │
└──────────────┘
Some files were skipped or only partially analyzed.
  Scan was limited to files tracked by git.
  Scan skipped: 8 files matching .semgrepignore patterns
  For a full list of skipped files, run opengrep with the --verbose flag.

Ran 1 rule on 24 files: 1 finding.
Not sending pseudonymous metrics since metrics are configured to AUTO and registry usage is False


┌────────────────┐
│ 1 Code Finding │
└────────────────┘

    owasp10.A03.data.access\Repositories\SqLiteRepository.cs
   ❯❯❱ rules.SQL-injection
          SQL injection vulnerability detected

           41┆ var sqlStatement = $"{SqlStatements.SELECT_ALL_CLAUSE} {tableName}
               {SqlStatements.WHERE_CLAUSE} {property} {SqlStatements.EQUAL_CLAUSE} '{value}'";
           42┆
           43┆ var records = await _context.QueryAsync(tableMapping, sqlStatement);
```

**JSON**

```
{
    "version": "2.1.0",
    "runs": [
        {
            "invocations": [
                {
                    "executionSuccessful": true,
                    "toolExecutionNotifications": []
                }
            ],
            "results": [
                {
                    "fingerprints": {
                        "matchBasedId/v1": "874ef5c895611e2e10a876e323e3b691a9b9a848a1991bfe3e9d0d1d9347c7a73e04912c7ca35b3e8bad33b939df58ccb2dc7b33fadfd8cc23159fef2aea9209_0"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "owasp10.A03.data.access\\Repositories\\SqLiteRepository.cs",
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "endColumn": 77,
                                    "endLine": 43,
                                    "snippet": {
                                        "text": "        var sqlStatement = $\"{SqlStatements.SELECT_ALL_CLAUSE} {tableName} {SqlStatements.WHERE_CLAUSE} {property} {SqlStatements.EQUAL_CLAUSE} '{value}'\";\n\n        var records = await _context.QueryAsync(tableMapping, sqlStatement);"
                                    },
                                    "startColumn": 13,
                                    "startLine": 41
                                }
                            }
                        }
                    ],
                    "message": {
                        "text": "SQL injection vulnerability detected"
                    },
                    "properties": {},
                    "ruleId": "rules.SQL-injection"
                }
            ],
            "tool": {
                "driver": {
                    "name": "Opengrep OSS",
                    "rules": [
                        {
                            "defaultConfiguration": {
                                "level": "warning"
                            },
                            "fullDescription": {
                                "text": "Review SQL queries for security vulnerabilities"
                            },
                            "help": {
                                "markdown": "Review SQL queries for security vulnerabilities\n\n<b>References:</b>\n - [https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2100](https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2100)\n",
                                "text": "Review SQL queries for security vulnerabilities"
                            },
                            "id": "rules.CA2100",
                            "name": "rules.CA2100",
                            "properties": {
                                "precision": "very-high",
                                "tags": [
                                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                    "security"
                                ]
                            },
                            "shortDescription": {
                                "text": "Opengrep Finding: rules.CA2100"
                            }
                        },
                        {
                            "defaultConfiguration": {
                                "level": "warning"
                            },
                            "fullDescription": {
                                "text": "Review code for SQL injection vulnerabilities"
                            },
                            "help": {
                                "markdown": "Review code for SQL injection vulnerabilities\n\n<b>References:</b>\n - [https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3001](https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3001)\n",
                                "text": "Review code for SQL injection vulnerabilities"
                            },
                            "id": "rules.CA3001",
                            "name": "rules.CA3001",
                            "properties": {
                                "precision": "very-high",
                                "tags": [
                                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                    "security"
                                ]
                            },
                            "shortDescription": {
                                "text": "Opengrep Finding: rules.CA3001"
                            }
                        },
                        {
                            "defaultConfiguration": {
                                "level": "error"
                            },
                            "fullDescription": {
                                "text": "SQL injection vulnerability detected"
                            },
                            "help": {
                                "markdown": "SQL injection vulnerability detected",
                                "text": "SQL injection vulnerability detected"
                            },
                            "id": "rules.SQL-injection",
                            "name": "rules.SQL-injection",
                            "properties": {
                                "precision": "very-high",
                                "tags": []
                            },
                            "shortDescription": {
                                "text": "Opengrep Finding: rules.SQL-injection"
                            }
                        },
                        {
                            "defaultConfiguration": {
                                "level": "error"
                            },
                            "fullDescription": {
                                "text": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a PreparedStatement using 'SqlCommand' and 'SqlParameter'."
                            },
                            "help": {
                                "markdown": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a PreparedStatement using 'SqlCommand' and 'SqlParameter'.\n\n<b>References:</b>\n - [https://owasp.org/Top10/A03_2021-Injection](https://owasp.org/Top10/A03_2021-Injection)\n",
                                "text": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a PreparedStatement using 'SqlCommand' and 'SqlParameter'."
                            },
                            "id": "rules.csharp-sqli",
                            "name": "rules.csharp-sqli",
                            "properties": {
                                "precision": "very-high",
                                "tags": [
                                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                    "MEDIUM CONFIDENCE",
                                    "OWASP-A01:2017 - Injection",
                                    "OWASP-A03:2021 - Injection",
                                    "security"
                                ]
                            },
                            "shortDescription": {
                                "text": "Opengrep Finding: rules.csharp-sqli"
                            }
                        }
                    ],
                    "semanticVersion": "1.4.2"
                }
            }
        }
    ],
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
}
```

#### Finding your way out with google dorks

Google dorks is an incredible tools for hacking at web browsers. It allows you to perform tailored queries through concrete operators. If you know what you are looking for, and Google has indexed it (weird, right?), you have chances of finding some juicy info.

And that works, as well, for technical information. My experience with Opengrep was lacking more customization of SQL injection rules, so I searched for configuration files with keywords in the text.

**Examples**

Find an yml config file in github with indicated keyword

```site:https://github.com ext:yaml intext:languages*csharp*```

Find an yml config file in github with complex keyword combination and or operator

```site:https://github.com ext:yaml intext:languages*csharp*message*"(sql | injection | sqli)"```

#### Links glossary

- **Aikido**: <https://www.aikido.dev/scanners/static-code-analysis-sast>
- **Trivy**: <https://trivy.dev/latest/>
- **Semgrep**: <https://semgrep.dev/>
- **Opengrep**: <https://github.com/opengrep/opengrep>
- **Opengrep rules datasource**: <https://github.com/opengrep/opengrep-rules>
- **Writing semgrep rules**: <https://semgrep.dev/docs/writing-rules/overview>
- **Semgrep rule playground**: <https://semgrep.dev/playground/new>
- **OWASP free SAST tools overview**: <https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools>
