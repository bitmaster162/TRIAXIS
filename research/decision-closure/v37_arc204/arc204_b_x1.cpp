#include <bits/stdc++.h>
using namespace std;

// For one permutation cycle, minimal sorting swaps recursively split the cycle.
// The point-bearing swaps (equal index modulo N) therefore form a
// monochromatic noncrossing forest on the cyclic order. Conversely, any
// monochromatic noncrossing forest can be completed to a noncrossing spanning
// tree, hence to a minimal swap factorization.
// If b is the minimum number of monochromatic blocks in a noncrossing
// partition of the cycle, the maximum number of point-bearing swaps is m-b.
//
// Standard noncrossing-partition recurrence:
// dp[l][r] = min blocks on the cyclic-order interval [l,r].
// Either l starts a new block, or it joins the block containing k>l of the
// same residue, with (l+1..k-1) nested inside.
// Each residue occurs at most K<=10 times globally.

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,K;
    if(!(cin>>N>>K)) return 0;
    int M=N*K;
    vector<int>P(M);
    for(int &x:P){ cin>>x; --x; }

    vector<char> vis(M,0);
    long long ans=0;

    for(int s=0;s<M;s++) if(!vis[s]){
        vector<int> cyc;
        int v=s;
        while(!vis[v]){
            vis[v]=1;
            cyc.push_back(v);
            v=P[v];
        }
        int m=(int)cyc.size();
        if(m<=1) continue;

        vector<int> col(m);
        for(int i=0;i<m;i++) col[i]=cyc[i]%N;

        vector<vector<int>> occ(N);
        for(int i=0;i<m;i++) occ[col[i]].push_back(i);

        vector<uint16_t> dp((size_t)m*m,0);
        auto at = [&](int l,int r)->uint16_t&{
            return dp[(size_t)l*m+r];
        };

        for(int l=m-1;l>=0;l--){
            at(l,l)=1;
            const auto &same=occ[col[l]];
            auto it0=upper_bound(same.begin(),same.end(),l);
            for(int r=l+1;r<m;r++){
                int best=1+(int)at(l+1,r);
                for(auto it=it0;it!=same.end() && *it<=r;++it){
                    int k=*it;
                    int mid = (k==l+1)?0:(int)at(l+1,k-1);
                    int cand = mid + (int)at(k,r);
                    if(cand<best) best=cand;
                }
                at(l,r)=(uint16_t)best;
            }
        }
        ans += m - (int)at(0,m-1);
    }

    cout<<ans<<"\n";
}
