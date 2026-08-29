#include <bits/stdc++.h>
using namespace std;

static uint64_t pack_state(int a,int c){
    return (uint64_t)(uint32_t)a<<32 | (uint32_t)c;
}
static pair<int,int> unpack_state(uint64_t z){
    int a=(int32_t)(z>>32);
    int c=(int32_t)(z&0xffffffffu);
    return {a,c};
}

struct Best{
    int score;
    string path;
};

static void relax(unordered_map<uint64_t,Best>& mp, int a,int c,int score, const string& path, char d){
    uint64_t key=pack_state(a,c);
    int ns=score + (a==0 && c==0 ? 1 : 0);
    auto it=mp.find(key);
    if(it==mp.end() || ns>it->second.score){
        string np=path;
        np.push_back(d);
        mp[key]={ns,move(np)};
    }
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    if(!(cin>>T)) return 0;
    while(T--){
        int N;
        string S;
        cin>>N>>S;

        unordered_map<uint64_t,Best> cur,nxt;
        cur.reserve(1024);
        cur[pack_state(0,0)]={0,string()};

        for(char ch:S){
            nxt.clear();
            nxt.reserve(cur.size()*3+8);
            for(auto &kv:cur){
                auto [a,c]=unpack_state(kv.first);
                const Best &b=kv.second;
                if(ch=='A'){
                    relax(nxt,a+2,c,b.score,b.path,'1');
                    relax(nxt,a-2,c-2,b.score,b.path,'2');
                    relax(nxt,a,c+2,b.score,b.path,'3');
                }else{
                    if(a==0) relax(nxt,0,c-1,b.score,b.path,'1');
                    if(c==0) relax(nxt,a-1,0,b.score,b.path,'3');
                }
            }
            cur.swap(nxt);
        }

        int best=-1000000000;
        string ans;
        for(auto &kv:cur){
            if(kv.second.score>best){
                best=kv.second.score;
                ans=kv.second.path;
            }
        }
        cout<<ans<<'\n';
    }
    return 0;
}
