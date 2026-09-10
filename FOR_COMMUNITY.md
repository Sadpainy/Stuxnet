# Why I shared this, and how I keep myself safe.

I'm not a company. I'm not a lab. I'm just someone who spent a long time reading public reports, looking at disassembly, and trying to understand how Stuxnet was built. I put what I learned into readable code. Not a weapon. A skeleton.

I know it's incomplete. I said so in the TODO file. No PLC payload. No working RPC logic. No real encryption keys. Just the structure, the module layout, the attack chain — enough for someone to study, not enough for someone to deploy.

Why share it at all? Because readable code is worth something. If you're learning ICS security, or writing detection rules, or just trying to understand how a piece of history was engineered, this gives you a starting point. That's it. That's the whole point.

As for safety — I don't use my real name. I don't use my home IP. I don't post from a machine tied to my identity. I don't need credit, I don't need a job offer, I don't need anyone to know who I am. The code speaks for itself. If it's useful, use it. If it's not, ignore it.

I'm not here to prove anything to anyone. I'm just here to share what I built.


# About the LLM thing

Yeah, I used an LLM to help clean things up. Not to write the logic — the logic came from reading reports, staring at disassembly, and piecing together how the original worked. But after I had the structure down, an LLM helped me organize it, format it, and make it readable.

Why not just leave it as raw, messy decompiler output? Because readable code is more useful. If someone wants to study this, they shouldn't have to fight through a wall of cryptic naming and inconsistent formatting. The LLM helped with that — cleaning up comments, tightening structure, making the modules easier to follow.

That's all it was. A tool. The same way I'd use a hex editor or a decompiler. It didn't replace the reverse engineering work — it just made the result easier to look at.

If you don't like that, fair enough. But the code is still the code. The structure is still the structure. The missing pieces are still missing. The LLM didn't change any of that.


# One more thing about LLMs

LLMs can hallucinate. They can fill in gaps that don't exist, make something look more complete than it really is. I'm not going to pretend that risk doesn't exist here.

If some part of this code looks off, or doesn't match what the public reports say, it might be because of that. I tried to catch it, but I can't guarantee I caught everything.

I'm not going to blame the LLM for that. It's a tool. Tools have limits. The responsibility for what's in here is mine.

So use this with your eyes open. Cross-check it against Symantec, ESET, Kaspersky. If something doesn't line up, trust the reports, not my code.

I hope this helps someone. That's all I wanted.

Thanks you watching this!
