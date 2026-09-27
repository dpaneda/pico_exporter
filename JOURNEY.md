# Why I built pico_exporter

A journal of how this project came to be: what I was trying to get, the
alternatives I tried, and why I ended up writing my own.

## The itch

I wanted system metrics out of a Raspberry Pi. It is a small machine with one
gigabyte of RAM. The standard answer is node_exporter plus something to ship
what it exposes, and between the two that came to about 60 or 70 MB.

As an old school person, I found that mildly offensive. Reading a few files
under `/proc` and POSTing the numbers somewhere is not a 70 MB problem.

## A note on how this was built

All of it was done with an LLM, mostly OpenCode on the free model. Not a
frontier model, then, and I suspect that is part of why I learned so much
along the way. The more you have to help it along, the more you have to
work out for yourself.

That matters for the rest of the story. How the model behaved, what it turned
out to be good at and where it stopped being useful, are interesting on their own
and there are a few conclusions worth writing down. They are at the end.

And yes, this text was written with the aid of an LLM too, but I read every word of
it. Most of it is basically a translation of my own words.

## Go: just replace the push

My first idea was to keep node_exporter and replace only the shipping,
because that looked easy. node_exporter already had all the logic in it. All
I had to do was take the metrics it exposes and push them to Grafana. I wrote
that in Go and it worked.

It was a miscalculation. The floor is too high. With the runtime in the
picture you are not getting under about 12 MB, no matter how little your
program does.

## Rust: 12 MB down to 4

So I moved to a language without that floor and reimplemented it in Rust. That
took it from 12 MB to about 4 MB, which felt acceptable at the time.

## Finding node_exporter-lite

Then I came across [node_exporter-lite](https://github.com/twekkel/node_exporter-lite),
where someone had reimplemented node_exporter in Nim. Less complete than the
original, but it had roughly what I needed, at about 1 MB. I tried it and it
did the job.

First I added the metrics it was missing for my use case. After that the next
move was obvious: Nim's footprint was so much smaller that I brought the Rust
code over too, and ended up with a single binary that collected the metrics
and shipped them. That put it at about 1.8 MB.

Which left the HTTP server as dead weight: nothing was scraping this any more.
Deleting it took 800 kB off and put the whole thing at about 1 MB.

## Where I could have stopped

I could have shipped it here. A megabyte is perfectly reasonable. It is small,
it fits on the Pi, nobody would notice it.

But by now it had turned into a personal challenge. How far could I take this?
How much more could I scrape off? One rule: it had to keep doing the job. No
cutting features because cutting them suited the number.

## Zig: a dead end

Nim's runtime is small, but it is still a runtime. There are allocation
details you cannot avoid paying for. You get no control over how memory is
allocated and no way to avoid some allocations at all.

So I wanted to try another language, and I went with Zig because it looked
pretty lightweight. It did not go well. I reimplemented it, trimmed what I
could, and there was nothing left to scrape.

## We all knew this was going to end in C

At that point I stopped messing around and wrote it in C, a language I know
better and one that gives me far more control.

What came out did the same as the Nim version at roughly the same footprint,
about 1 MB. The difference was that now I could see what it was doing.

## Minimising the code size

By now the code itself was a large share of the RSS. Everything in this
section is the same move repeated: take a big dependency out, put a smaller
one in.

The libc first. A lot of the footprint lived in there, so I moved to musl,
which is considerably smaller.

Then further. musl is small, but there are libcs written for embedded targets,
and that is where I started looking. After trying a few, picolibc fit best.
That had consequences. picolibc does not do name resolution, so resolving the
gateway's hostname became my problem, and that is why there is a DNS client in
this repo.

Then TLS, same reason. I had started on WolfSSL, picked because it was a lot
smaller than OpenSSL, which is where the model reached first and which for
this use case would have been an atrocity. BearSSL is smaller still, and it
has a second advantage that matters more than the size: it does not allocate
dynamically. You get total control. It wants some things handed to it
statically, which here is exactly what you want.

Then I cut it down further. The client supports exactly one cipher suite and
exactly one curve, because everything else is code that ships and never runs.
That is a real trade and not a free win: narrow your suite list far enough and
you stop being able to talk to endpoints you have not met yet.

Compiler flags turned out to be worth a surprising amount on their own. There
are flags that let the linker throw away every function nothing calls, flags
that optimise for size instead of speed, flags that drop metadata the program
never uses. None of it changes the code. It just stops shipping the parts that
were never going to run.

And this went further than my own build. picolibc and BearSSL get recompiled
from source too, with the same flags and with their own features switched off,
so the libraries I link against are smaller than the ones you would get off
the shelf.

By the end of this process I brought it down to about 400 kB.

## No mallocs: the arena

The other obvious move for control over memory was to stop calling malloc.
Whichever library you use, once you malloc it is that library's runtime
deciding when the memory actually goes back, not you.

So I wrote my own small allocator. There is an arena, and from then on
everything was either stack or came out of the arena. There is a malloc
fallback, but it should never fire. It is there for stability and nothing
reaches it under normal conditions.

That got it to around 230 kB.

## Buffers, and the arena at rest

By now the RSS cost of the code was basically the floor for this use case, so
the next round was about buffer sizes.

Plenty of them were sized for a worst case that never happens: an array with
room for 64 devices on a machine that has two. Reserve the two, keep an
overflow path in case some machine really does have more, and you save a lot.
Same story with the labels a metric can carry, which multiplied by every
metric in the export adds up.

The other big win for resting RSS was the arena. It takes its memory in one
anonymous `mmap` and bump allocates out of it, and the important part is what
`arena_reset()` does at the end of every cycle:

```c
madvise(a->base, a->cap, MADV_DONTNEED);
```

That hands the pages back to the kernel and sets the offset to zero. The
mapping stays, the pages do not. They get faulted back in next cycle, so the
arena costs nothing at rest. The peak is real while a cycle runs, but the
steady state does not carry it.

This was one of the best parts of the whole project. Trying to scrape off
bytes this hard teaches you an enormous amount about exactly how memory is
handled by the compiler, the linker and the OS itself.

Another interesting case at this point was measuring. I kept saving bytes and
RSS would not move, and the problem turned out to be the measurement, not
the code: the kernel only [updates it every 64 page faults](https://github.com/torvalds/linux/blob/v6.1/mm/memory.c#L198),
and a cycle here faults nowhere near that many. The only way to see the spike was to count the
faults directly (`minflt` in `/proc/<pid>/stat`).

All of that lands at the roughly 120 kB it sits at today. I would have liked
to get under 100 kB and I do not see how. If you can, the repo is right
here.

## 2026-09-25 Cheating the system

Working on another project where I tried to achieve the minimum RSS possible for
a process give me an idea and I was able to gain another 5x with an ugly hack.
Right now most of the memory is evictable memory, mainly code pages. But we don't
need the code pages when we go to sleep right? So we just need to ask the kernel
to evict all the in the same way that we did with the arena. The (very obscure)
implementation of that is on https://github.com/dpaneda/pico_exporter/pull/1, with a
nice touch of a faster scrape time due to reading files with just syscalls, no stdio.

This is not really a reasonable thing to do in general obviously. The kernel will
need to get those pages on every cycle. Although is very little memory, so is a very
cheap thing to do in this case.

Now it seems the the memory floor is hard to move, with 28 KiB at rest.

## What the LLM was good at, and what it was not

The implementation work by the LLM was genuinely impressive sometimes. It wrote
and validated the code, and practically everything worked on the first try. My
job was checking that the metrics were the ones I actually wanted and adjusting
small things around the edges. It also did a good job creating tests to guide
reimplementation in other languages.

What it could not do was take the steps that moved the needle. Steps like moving
the entire thing to another language, removing the web server, or using an arena.
The model was very good at measuring where the memory was going, but it was not able
to suggest the changes that really moved the needle in terms of resources.
