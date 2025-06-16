package util

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"tilok.dev/dns-checker/types"
)

func Hash(strs []string) string {
	if len(strs) == 0 {
		return ""
	}

	strs = slices.Clone(strs)

	slices.Sort(strs)

	hasher := sha256.New()
	for _, str := range strs {
		hasher.Write([]byte(str))
	}
	hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return hash
}

func CountResults(results []types.DnsResult) types.DnsCounts {
	addrCounts := make(map[string]int)
	cnameCounts := make(map[string]int)
	txtCounts := make(map[string]int)
	nsCounts := make(map[string]int)

	for _, result := range results {
		addrHash := Hash(result.Addreses)
		cnameHash := Hash([]string{result.Cname})
		txtHash := Hash(result.Txts)
		nsHash := Hash(result.Ns)

		addrCounts[addrHash] = addrCounts[addrHash] + 1
		cnameCounts[cnameHash] = cnameCounts[cnameHash] + 1
		txtCounts[txtHash] = txtCounts[txtHash] + 1
		nsCounts[nsHash] = nsCounts[nsHash] + 1
	}

	highestAddrCount := 0
	highestAddrStr := ""
	highestCnameCount := 0
	highestCnameStr := ""
	highestTxtCount := 0
	highestTxtStr := ""
	highestNsCount := 0
	highestNsStr := ""

	for hash, count := range addrCounts {
		if count > highestAddrCount {
			highestAddrCount = count
			highestAddrStr = hash
		}
	}

	for hash, count := range cnameCounts {
		if count > highestCnameCount {
			highestCnameCount = count
			highestCnameStr = hash
		}
	}

	for hash, count := range txtCounts {
		if count > highestTxtCount {
			highestTxtCount = count
			highestTxtStr = hash
		}
	}

	for hash, count := range nsCounts {
		if count > highestNsCount {
			highestNsCount = count
			highestNsStr = hash
		}
	}

	return types.DnsCounts{
		Addreses: highestAddrStr,
		Cname:    highestCnameStr,
		Txts:     highestTxtStr,
		Ns:       highestNsStr,
	}
}
