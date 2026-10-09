#include <bits/stdc++.h>
using namespace std;

using int64 = long long;
static const int SCORE_BOUND = 12;

static vector<array<unsigned char,32>> build_signatures(){
    unordered_set<string> seen;
    vector<array<unsigned char,32>> out;
    int q[5];
    for(q[0]=1;q[0]<=SCORE_BOUND;q[0]++)
    for(q[1]=q[0];q[1]<=SCORE_BOUND;q[1]++)
    for(q[2]=q[1];q[2]<=SCORE_BOUND;q[2]++)
    for(q[3]=q[2];q[3]<=SCORE_BOUND;q[3]++)
    for(q[4]=q[3];q[4]<=SCORE_BOUND;q[4]++){
        vector<pair<int,int>> v;
        v.reserve(31);
        for(int m=1;m<32;m++){
            int s=0;
            for(int j=0;j<5;j++) if(m>>j&1) s+=q[j];
            v.push_back({-s,m});
        }
        sort(v.begin(),v.end());
        array<unsigned char,32> g{};
        int gid=-1, prevScore=INT_MIN;
        for(auto [neg,m]:v){
            int s=-neg;
            if(gid<0 || s!=prevScore){ ++gid; prevScore=s; }
            g[m]=(unsigned char)gid;
        }
        string key;
        key.resize(31);
        for(int m=1;m<32;m++) key[m-1]=(char)g[m];
        if(seen.insert(key).second) out.push_back(g);
    }
    return out;
}

static inline int64 sqpref(int64 n){
    if(n<=0) return 0;
    return n*(n+1)*(2*n+1)/6;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    const auto signatures=build_signatures();
    unordered_map<uint32_t, vector<string>> patternCache;

    int T; cin >> T;
    while(T--){
        int N; cin >> N;
        vector<int> masks(N);
        uint32_t present=0;
        for(int i=0;i<N;i++){
            int m=0;
            for(int j=0;j<5;j++){
                int b; cin >> b;
                if(b) m|=1<<j;
            }
            masks[i]=m;
            present |= 1u<<(m-1);
        }
        vector<vector<int>> ranks(32);
        for(int i=0;i<N;i++){
            int r; cin >> r;
            ranks[masks[i]].push_back(r);
        }
        vector<int> cats;
        for(int m=1;m<32;m++) if(!ranks[m].empty()){
            sort(ranks[m].begin(),ranks[m].end());
            cats.push_back(m);
        }
        int K=(int)cats.size();
        vector<int64> cnt(32), sum(32), sumsq(32), phi(32);
        for(int m:cats){
            cnt[m]=ranks[m].size();
            for(int i=0;i<(int)ranks[m].size();i++){
                int64 r=ranks[m][i];
                sum[m]+=r;
                sumsq[m]+=r*r;
                phi[m]+=(int64)(i+1)*r;
            }
        }
        int64 cross[32][32]{};
        for(int ia=0;ia<K;ia++) for(int ib=ia+1;ib<K;ib++){
            int a=cats[ia], b=cats[ib];
            const auto &A=ranks[a], &B=ranks[b];
            vector<int64> pref(B.size()+1,0);
            for(size_t i=0;i<B.size();i++) pref[i+1]=pref[i]+B[i];
            int64 val=0;
            for(int x:A){
                size_t p=upper_bound(B.begin(),B.end(),x)-B.begin();
                val += (int64)x*(int64)p + (pref[B.size()]-pref[p]);
            }
            cross[a][b]=cross[b][a]=val;
        }

        auto it=patternCache.find(present);
        if(it==patternCache.end()){
            unordered_set<string> uniq;
            vector<string> pats;
            pats.reserve(signatures.size());
            for(const auto &sg:signatures){
                vector<pair<int,int>> tmp;
                tmp.reserve(K);
                for(int i=0;i<K;i++) tmp.push_back({(int)sg[cats[i]],i});
                sort(tmp.begin(),tmp.end());
                string pat(K,'\0');
                int ng=-1, prev=-1;
                for(auto [gg,idx]:tmp){
                    if(ng<0 || gg!=prev){ ++ng; prev=gg; }
                    pat[idx]=(char)ng;
                }
                if(uniq.insert(pat).second) pats.push_back(pat);
            }
            it=patternCache.emplace(present,move(pats)).first;
        }

        int64 best=LLONG_MAX;
        for(const string &pat:it->second){
            int maxg=0;
            for(unsigned char c:pat) maxg=max(maxg,(int)c);
            int64 cost=0;
            int64 leftRank=1;
            for(int g=0;g<=maxg;g++){
                vector<int> members;
                int64 ctot=0, stot=0, s2tot=0, phitot=0;
                for(int i=0;i<K;i++) if((unsigned char)pat[i]==g){
                    int m=cats[i];
                    members.push_back(m);
                    ctot+=cnt[m]; stot+=sum[m]; s2tot+=sumsq[m]; phitot+=phi[m];
                }
                for(int i=0;i<(int)members.size();i++)
                    for(int j=i+1;j<(int)members.size();j++)
                        phitot+=cross[members[i]][members[j]];
                int64 rightRank=leftRank+ctot-1;
                int64 posSq=sqpref(rightRank)-sqpref(leftRank-1);
                cost += s2tot + posSq - 2*((leftRank-1)*stot + phitot);
                leftRank=rightRank+1;
            }
            best=min(best,cost);
        }
        cout << best << '\n';
    }
    return 0;
}
