#include <bits/stdc++.h>
using namespace std;
static const int MOD=998244353;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,M;
    cin>>N>>M;
    vector<vector<int>> P(M, vector<int>(N));
    for(int k=0;k<M;k++) for(int u=0;u<N;u++) cin>>P[k][u];

    int root=-1;
    for(int u=0;u<N;u++) if(P[0][u]==1) root=u;

    vector<int> vertex_at_refpos(N+1);
    for(int u=0;u<N;u++) vertex_at_refpos[P[0][u]]=u;

    int n=N-1;
    vector<vector<unsigned char>> common(n, vector<unsigned char>(n,1));

    // Cut every circular order at the same root vertex. Any subtree not
    // containing the global root is then an ordinary interval.
    for(int k=0;k<M;k++){
        int pr=P[k][root];
        vector<int> a(n);
        for(int x=2;x<=N;x++){
            int u=vertex_at_refpos[x];
            int d=P[k][u]-pr;
            d%=N; if(d<0) d+=N;
            a[x-2]=d; // in 1..N-1
        }
        for(int l=0;l<n;l++){
            int mn=INT_MAX,mx=INT_MIN;
            for(int r=l;r<n;r++){
                mn=min(mn,a[r]); mx=max(mx,a[r]);
                if(mx-mn+1 != r-l+1) common[l][r]=0;
            }
        }
    }

    if(n==0){ cout<<1<<"\n"; return 0; }

    vector<vector<int>> G(n, vector<int>(n,0));
    vector<vector<int>> S(n, vector<int>(n,0));

    auto getS = [&](int l,int r)->int{
        return l>r ? 1 : S[l][r];
    };

    for(int len=1;len<=n;len++){
        // G[l][r] = number of valid rooted trees on this block,
        // summed over the attachment/root vertex.
        for(int l=0;l+len<=n;l++){
            int r=l+len-1;
            if(!common[l][r]) continue;
            long long val=0;
            for(int v=l;v<=r;v++){
                val += 1LL*getS(l,v-1)*getS(v+1,r)%MOD;
                if(val >= (1LL<<62)) val%=MOD;
            }
            G[l][r]=val%MOD;
        }
        // S[l][r] = ordered forest of consecutive common-interval blocks.
        for(int l=0;l+len<=n;l++){
            int r=l+len-1;
            long long val=0;
            for(int k=l;k<=r;k++){
                val += 1LL*G[l][k]*getS(k+1,r)%MOD;
                if(val >= (1LL<<62)) val%=MOD;
            }
            S[l][r]=val%MOD;
        }
    }
    cout<<S[0][n-1]<<"\n";
}
