#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

long long modpow(long long a,long long e){
    long long r=1;
    while(e){
        if(e&1) r=r*a%MOD;
        a=a*a%MOD;
        e>>=1;
    }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<int>A(N+1);
    for(int i=1;i<=N;i++) cin>>A[i];

    vector<int> leftc(N+1), rightc(N+1), parent(N+1), st;
    st.reserve(N);

    for(int i=1;i<=N;i++){
        int last=0;
        while(!st.empty() && st.back()!=A[i]){
            last=st.back();
            st.pop_back();
        }
        if(A[i]==0){
            // Valid inputs force the stack to be empty here.
            if(!st.empty()){
                cout<<0<<'\n';
                return 0;
            }
        }else{
            if(st.empty() || st.back()!=A[i]){
                cout<<0<<'\n';
                return 0;
            }
        }

        if(!st.empty()){
            parent[i]=st.back();
            rightc[st.back()]=i;
        }
        if(last){
            parent[last]=i;
            leftc[i]=last;
        }
        st.push_back(i);
    }

    int root=0;
    for(int i=1;i<=N;i++) if(parent[i]==0){ root=i; break; }

    vector<int> order;
    order.reserve(N);
    vector<int> q;
    q.push_back(root);
    while(!q.empty()){
        int u=q.back(); q.pop_back();
        order.push_back(u);
        if(leftc[u]) q.push_back(leftc[u]);
        if(rightc[u]) q.push_back(rightc[u]);
    }
    if((int)order.size()!=N){
        cout<<0<<'\n';
        return 0;
    }

    vector<int> sz(N+1,1);
    for(int k=N-1;k>=0;k--){
        int u=order[k];
        if(leftc[u]) sz[u]+=sz[leftc[u]];
        if(rightc[u]) sz[u]+=sz[rightc[u]];
    }

    long long ans=1;
    for(int i=1;i<=N;i++) ans=ans*i%MOD;
    for(int i=1;i<=N;i++) ans=ans*modpow(sz[i],MOD-2)%MOD;
    cout<<ans<<'\n';
    return 0;
}
