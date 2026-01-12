package bip39

// WordList represents a BIP-39 word list.
type WordList interface {
	// Words returns all words in the word list.
	Words() []string

	// WordIndex returns the index of a word in the word list.
	// Returns -1 if the word is not found.
	WordIndex(word string) int

	// WordAt returns the word at the given index.
	// Panics if index is out of range.
	WordAt(index int) string

	// Size returns the number of words in the word list (should be 2048).
	Size() int
}

// wordListImpl implements WordList interface.
type wordListImpl struct {
	words   []string
	wordMap map[string]int
}

// newWordList creates a new word list from a slice of words.
func newWordList(words []string) *wordListImpl {
	wordMap := make(map[string]int, len(words))
	for i, word := range words {
		wordMap[word] = i
	}
	return &wordListImpl{
		words:   words,
		wordMap: wordMap,
	}
}

func (w *wordListImpl) Words() []string {
	return w.words
}

func (w *wordListImpl) WordIndex(word string) int {
	if idx, ok := w.wordMap[word]; ok {
		return idx
	}
	return -1
}

func (w *wordListImpl) WordAt(index int) string {
	return w.words[index]
}

func (w *wordListImpl) Size() int {
	return len(w.words)
}

// English is the official BIP-39 English word list.
var English WordList = newWordList(englishWords)

// DefaultWordList is the default word list used for mnemonic generation.
var DefaultWordList = English
