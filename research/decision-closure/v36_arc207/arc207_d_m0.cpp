#include <bits/stdc++.h>
using namespace std;

// ARC207 D - M0
// Repeatedly adding one row at both the top/bottom (or one column at both
// left/right) beyond the stable central size does not change the alternating
// OR/AND minimax formula: the two extra moves cancel by absorption.
// Hence an odd dimension >=3 reduces to its central 3 cells and an even
// dimension >=4 reduces to its central 4 cells. Dimensions 1 and 2 stay as-is.
// The remaining game is at most 4x4 and is evaluated exactly.

struct Solver {
    int H, W;
    vector<string> a;
    int memo[4][4][4][4];
    bool vis[4][4][4][4];

    int go(int u, int d, int l, int r) {
        int &res = memo[u][d][l][r];
        if (vis[u][d][l][r]) return res;
        vis[u][d][l][r] = true;
        if (u == d && l == r) return res = (a[u][l] == '1');

        int removed = (H - (d-u+1)) + (W - (r-l+1));
        bool first = (removed % 2 == 0);
        if (first) {
            res = 0;
            if (u < d) {
                res |= go(u+1,d,l,r);
                res |= go(u,d-1,l,r);
            }
            if (l < r) {
                res |= go(u,d,l+1,r);
                res |= go(u,d,l,r-1);
            }
        } else {
            res = 1;
            if (u < d) {
                res &= go(u+1,d,l,r);
                res &= go(u,d-1,l,r);
            }
            if (l < r) {
                res &= go(u,d,l+1,r);
                res &= go(u,d,l,r-1);
            }
        }
        return res;
    }
};

static int core_dim(int n) {
    if (n <= 2) return n;
    return (n & 1) ? 3 : 4;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    while (T--) {
        int N, M;
        cin >> N >> M;
        vector<string> s(N);
        for (auto &row : s) cin >> row;

        int H = core_dim(N), W = core_dim(M);
        int rs = (N - H) / 2;
        int cs = (M - W) / 2;

        Solver sol;
        sol.H = H; sol.W = W;
        sol.a.assign(H, string(W, '0'));
        memset(sol.vis, 0, sizeof(sol.vis));
        for (int i=0;i<H;i++)
            for (int j=0;j<W;j++)
                sol.a[i][j] = s[rs+i][cs+j];

        cout << (sol.go(0,H-1,0,W-1) ? "First" : "Second") << '\n';
    }
    return 0;
}
