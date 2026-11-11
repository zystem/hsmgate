# Writing the documents

What the project holds its pages to. Short, because most of it is checked by a test, not by a promise.

**One kind of page.** A tutorial shows one path that works, with what you will see after each step, and offers no options. A how-to guide gets one task done and teaches nothing else. A reference is complete, dry and in the shape of the program (it is consulted, not read). An explanation says why. Link between them instead of mixing them ([README, "What kind of page is it"](README.md)).

**A command comes with what it prints.** A reader who cannot see the expected output cannot tell whether it worked. Show the command and then its output, as the README and [guides/clients.md](guides/clients.md) do; say when the output is cut.

**Say what is not known.** What was run and what was not, on what ([transit-face.md](transit-face.md), "Verified" sections; the chart README). A claim that was never run is written as "not run", never as a fact. Dates are absolute (2026-11-12), not "recently".

**Defaults and requirements are stated**, in [configuration.md](configuration.md): what is required, what happens when a setting is left out, and whether a change needs a restart or a reload. "No limit" is a default that must be written down.

**A test keeps a page true where it can.** The pages that are checked:

| Page | What the test compares it with |
|---|---|
| [cli.md](cli.md) | what `hsmgate <command> -h` prints (`go test ./cmd/hsmgate -run CLIReference -update` rewrites it) |
| [configuration.md](configuration.md) | every setting of the configuration struct is named; the stated defaults are the code's |
| [audit-log.md](audit-log.md) | the fields of an audit line, the class of each result word |
| [operations.md](operations.md), [long-running-checks.md](long-running-checks.md) | every metric the service writes is named |
| the README, "Try it" | the commands are run against `hsmgate dev` and the output shown is what they print |
| `deploy/hsmgate.example.yaml`, `deploy/hsmgate.minimal.yaml` | they load as configurations |

A new setting, flag, audit field or metric fails one of these until its page says what it is. When you add a page that states facts of the program, add the test next to the code it describes.

**Names.** A cloud vendor's name appears only where a wire format needs it; elsewhere use a neutral name, or the name of the client function in [go.step.sm/crypto/kms](https://github.com/smallstep/crypto#kms) that the face serves ([CONTRIBUTING.md](../CONTRIBUTING.md)).

**Troubleshooting is by message.** When you add an error message that a user can see, add its row to [troubleshooting.md](troubleshooting.md): the message, what it means, what to do.

**English, plain.** Short sentences, the word the program uses (token, key, client, context, face: [the glossary in the README](../README.md#words)), no word a newcomer has to look up without a link.
