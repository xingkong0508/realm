#include <math.h>
#include <stdbool.h>

// evaluate_realm_sovereignty: 核心审判逻辑 (透明开源版)
// 算法公式完全公开，接受全球极客审计，绝无后门。
// 但核心的控制参数 score_divider 和 threshold_multiplier 由外层引擎动态注入。
bool evaluate_realm_sovereignty(double entropy, double mean, double stddev, double score_divider, double threshold_multiplier) {
    // 防止除零异常
    if (stddev == 0) return false;

    // 核心判定公式 (公开)
    double score = (entropy - mean) / (stddev * score_divider);
    double threshold = threshold_multiplier * log10(mean + 1.1);

    return score > threshold;
}
