const BACKEND_HOST = "http://localhost:9090"
async function searchForPseudonym(record, keywords, fuzzy) {
    const response = await fetch(`${BACKEND_HOST}/requestPseudonym`, {
        method: "POST",
        body: JSON.stringify({
            "data": record,
            "keywords": keywords,
            "is_fuzzy": fuzzy
        }
        ),
        headers: { 'Content-Type': 'application/json' },
    })
    const searchResults = await response.json()
    console.log(searchResults)
    return searchResults
}

export async function submitForm() {
    const usedAsKeywords = [this.firstNameIsKeyword, this.surnameIsKeyword, this.sidIsKeyword]
    const valuesDict = { "name": this.firstName, "surname": this.surname, "sid": this.sid }
    let keywords = []
    Object.entries(valuesDict).forEach(([key, value], index) => {
        if (usedAsKeywords[index]) keywords.push(key)
    });
    const searchResults = await searchForPseudonym(valuesDict, keywords, this.isFuzzySearch)
    this.searchResults = searchResults[0][1]
    this.decryptedData = searchResults[0][0]//Object.values(searchResults[0][0])
    console.log(this.decryptedData, this.searchResults)
}