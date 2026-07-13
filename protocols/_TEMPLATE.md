# Protocol-reference authoring template (follow this per protocol)

Audience: a beginner who has NOT heard of these protocols. Be precise but explain jargon on first use.
Write Markdown. For EACH protocol in your assigned file, use this structure:

## <PROTOCOL> — <full name>
- **What it is / meaning:** one plain-language paragraph. Expand the acronym. Which RAT(s) use it, which
  layer it sits at, and what sits above/below it in the stack.
- **Purpose:** what job it does (2–4 bullets).
- **Specification:** the 3GPP TS (or IETF RFC) number(s) that define it, with a working link. Use the
  canonical sources: 3GPP spec browser `https://portal.3gpp.org/` and the direct spec search
  `https://www.3gpp.org/dynareport?code=<NN.NNN>.htm` (e.g. code=38.321), ShareTechnote
  `https://www.sharetechnote.com/`, and for IETF `https://datatracker.ietf.org/doc/html/rfcNNNN`.
- **Packet / PDU disposition (how it looks on the wire):** an ASCII diagram of the header/PDU layout with
  the real field names and bit widths **from the spec**. Label each field. If a format has variants
  (e.g. fixed vs variable, UM vs AM), show the common ones. **Accuracy rule:** only state bit widths you
  are confident are correct from the spec; if unsure of an exact width, describe the field and add
  "(width per TS <x> §<y> — verify)" rather than inventing a number.
- **Key fields explained:** a short table of the important fields and what each means/does.
- **Beginner notes / gotchas:** things that confuse newcomers (naming clashes, CS vs PS, per-RAT
  differences, etc.).
- **Security relevance:** where attacker-controlled data enters, whether it's pre-/post-auth, and which
  of this project's findings (if any) live in this protocol. Reachability tier if applicable.

Keep each protocol to ~1 screen. Prefer correctness over length. Use ASCII boxes like:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Field A      |  B  |            Field C ...              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
Start the file with a 2-3 sentence intro placing these protocols in the stack, and a mini table of
contents. Cross-reference `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` for the big picture.
