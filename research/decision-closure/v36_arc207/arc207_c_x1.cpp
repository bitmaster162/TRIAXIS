#include <bits/stdc++.h>
using namespace std;

// ARC207 C - X1
// Frozen feedback showed that a single greedy last-OR state is insufficient:
// [2,1,4,4] is optimally [2|1],[4],[4].
// Correction: retain the exact frontier of possible last-block OR values.
// At every new element x, each prior state (last=v, blocks=k) has exactly two
// legal continuations:
//   1) merge x into the last block -> (v|x, k)
//   2) if v<=x, start a new singleton block -> (x, k+1)
// The last block is always the OR of a suffix ending at the current position,
// so there are at most 30 distinct OR values. Complexity O(30N).

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<unsigned int>A(N);
    for(auto &x:A) cin>>x;

    vector<pair<unsigned int,int>> st;
    st.push_back({A[0],1});

    for(int i=1;i<N;i++){
        unsigned int x=A[i];
        vector<pair<unsigned int,int>> raw;
        raw.reserve(st.size()+1);

        int bestStart=-1;
        for(auto [v,k]:st){
            raw.push_back({v|x,k});
            if(v<=x) bestStart=max(bestStart,k+1);
        }
        if(bestStart>=0) raw.push_back({x,bestStart});

        sort(raw.begin(),raw.end(),[](auto &a,auto &b){return a.first<b.first;});
        vector<pair<unsigned int,int>> nxt;
        for(auto [v,k]:raw){
            if(!nxt.empty() && nxt.back().first==v)
                nxt.back().second=max(nxt.back().second,k);
            else
                nxt.push_back({v,k});
        }

        vector<pair<unsigned int,int>> pruned;
        int best=-1;
        for(auto [v,k]:nxt){
            if(k>best){
                pruned.push_back({v,k});
                best=k;
            }
        }
        st.swap(pruned);
    }

    int ans=0;
    for(auto [v,k]:st) ans=max(ans,k);
    cout<<ans<<'\n';
    return 0;
}
