package engine

import "math"

func CalculateShannonEntropy(data []byte) float64 {
if len(data) == 0 { return 0.0 }
frequencies := make(map[byte]float64)
for _, b := range data { frequencies[b]++ }
entropy := 0.0
dataLen := float64(len(data))
for _, freq := range frequencies {
probability := freq / dataLen
entropy -= probability * math.Log2(probability)
}
return entropy
}

type LawEngine struct {
Alpha      float64
Mean       float64
M2         float64
Count      int64
K          float64
IsPunished bool
}

func NewLawEngine(alpha, k float64) *LawEngine {
return &LawEngine{Alpha: alpha, K: k, IsPunished: false}
}

func (e *LawEngine) Punish() {
e.K = 1.5           
e.Alpha = 0.0001    
e.IsPunished = true
}

func (e *LawEngine) Restore() {
e.K = 3.0
e.Alpha = 0.01
e.IsPunished = false
}

func (e *LawEngine) UpdateOnly(entropy float64) {
e.Count++
if e.Count == 1 {
e.Mean = entropy
return
}
delta := entropy - e.Mean
e.Mean = (e.Alpha * entropy) + ((1 - e.Alpha) * e.Mean)
e.M2 += delta * (entropy - e.Mean)
}
