#include <bits/stdc++.h>
using namespace std;

struct Node {
    unsigned long long parent;
    int op;
    unsigned long long val;
    bool has_parent;
};

static inline unsigned long long step_mask(unsigned long long s, int i) {
    unsigned long long a=(s>>i)&1ULL, b=(s>>(i+1))&1ULL;
    unsigned long long x=a^b;
    unsigned long long bits=(1ULL<<i)|(1ULL<<(i+1));
    s &= ~bits;
    if(x) s |= bits;
    return s;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T; cin>>T;
    while(T--){
        int N; unsigned long long K;
        cin>>N>>K;
        vector<unsigned long long>A(N);
        for(auto &x:A) cin>>x;

        unordered_map<unsigned long long,Node> mp;
        mp.reserve(1<<16);
        queue<unsigned long long> q;
        unsigned long long start=1ULL;
        mp.emplace(start, Node{0,-1,A[0],false});
        q.push(start);
        unsigned long long goal=~0ULL;
        while(!q.empty()){
            auto s=q.front(); q.pop();
            auto cur=mp.find(s)->second;
            if(cur.val==K){ goal=s; break; }
            for(int i=0;i<N-1;i++){
                auto t=step_mask(s,i);
                if(mp.find(t)!=mp.end()) continue;
                unsigned long long nv=cur.val;
                if(((s>>i)&1ULL)!=((t>>i)&1ULL)) nv^=A[i];
                if(((s>>(i+1))&1ULL)!=((t>>(i+1))&1ULL)) nv^=A[i+1];
                mp.emplace(t, Node{s,i+1,nv,true});
                q.push(t);
            }
        }
        if(goal==~0ULL){
            cout<<"No\n";
            continue;
        }
        vector<int> rev;
        unsigned long long s=goal;
        while(mp[s].has_parent){
            rev.push_back(mp[s].op);
            s=mp[s].parent;
        }
        // Coefficient-row evolution is the reverse chronological order
        // of operations on the actual value vector.
        reverse(rev.begin(),rev.end());
        cout<<"Yes\n"<<rev.size()<<"\n";
        for(size_t i=0;i<rev.size();i++){
            if(i) cout<<' ';
            cout<<rev[i];
        }
        cout<<"\n";
    }
}
