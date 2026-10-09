#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,Q;
    if(!(cin>>N>>Q)) return 0;
    int NN=N*N;
    const int MAXS=900;
    using BS = bitset<MAXS+1>;

    vector<vector<BS>> dp(N+1, vector<BS>(N+1));
    dp[0][0].set(0);

    // Each nontrivial SCC of an oriented K_{N,N} must contain
    // at least two row vertices and two column vertices, and contributes
    // a*b non-fixed cells. Different SCCs use disjoint row/column budgets.
    for(int r=0;r<=N;r++){
        for(int c=0;c<=N;c++){
            if(dp[r][c].none()) continue;
            for(int a=2;r+a<=N;a++){
                for(int b=2;c+b<=N;b++){
                    dp[r+a][c+b] |= (dp[r][c] << (a*b));
                }
            }
        }
    }

    BS possibleNonfixed;
    for(int r=0;r<=N;r++)
        for(int c=0;c<=N;c++)
            possibleNonfixed |= dp[r][c];

    while(Q--){
        int K; cin>>K;
        int nonfixed=NN-K;
        cout << (possibleNonfixed.test(nonfixed) ? "Yes" : "No") << '\n';
    }
    return 0;
}
