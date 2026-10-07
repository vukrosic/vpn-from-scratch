"""Step 6: replays. A recorded packet is still a valid packet, so the receiver must remember what it has seen."""


class Window:
    """Remembers which counters arrived: the highest one, and one bit for each of 63 before it."""
    SIZE = 64

    def __init__(self):
        self.top, self.bits = -1, 0

    def fresh(self, n):
        """True the first time counter n arrives. False for a repeat, or one too old to remember."""
        if n > self.top:
            self.bits = (self.bits << (n - self.top) | 1) & (2 ** self.SIZE - 1)
            self.top = n
            return True
        back = self.top - n
        if back >= self.SIZE or self.bits >> back & 1:
            return False
        self.bits |= 1 << back
        return True


if __name__ == '__main__':
    window = Window()
    for n in [0, 1, 2, 4, 3, 3, 1, 70, 69, 7, 6]:
        why = 'new' if n > window.top else 'late, but new' if window.top - n < 64 else 'too old to remember'
        ok = window.fresh(n)
        print(f'  counter {n:>2}: {"accept" if ok else "DROP  "}  {why if ok or "old" in why else "seen before"}')
