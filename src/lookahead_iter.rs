pub struct LookaheadIterator<I>
where
    I: Iterator,
{
    iter: I,
    buffer: Vec<I::Item>,
}

impl<I> LookaheadIterator<I>
where
    I: Iterator,
{
    pub fn new(iter: I) -> Self {
        LookaheadIterator {
            iter,
            buffer: Vec::new(),
        }
    }

    /// Ensures that at least `n` items are buffered and returns a slice of them.
    pub fn peek_n(&mut self, n: usize) -> &[I::Item] {
        // Keep filling the buffer until we have n items or the iterator is exhausted.
        while self.buffer.len() < n {
            if let Some(item) = self.iter.next() {
                self.buffer.push(item);
            } else {
                break;
            }
        }
        &self.buffer[..]
    }
}

impl<I> Iterator for LookaheadIterator<I>
where
    I: Iterator,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.buffer.is_empty() {
            // Remove the first buffered item.
            Some(self.buffer.remove(0))
        } else {
            self.iter.next()
        }
    }
}
