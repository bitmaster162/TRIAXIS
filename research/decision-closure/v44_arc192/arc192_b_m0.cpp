#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    cin>>N;
    vector<long long>A(N);
    for(auto &x:A) cin>>x;

    bool fennec;
    if(N==1){
        fennec=true;
    }else if(N==2){
        fennec=false;
    }else if(N==3){
        bool allEven=true;
        for(long long x:A) if(x&1) allEven=false;
        fennec=!allEven;
    }else{
        int odd=0;
        for(long long x:A) odd += (x&1);
        fennec = (odd&1);
    }

    cout<<(fennec ? "Fennec" : "Snuke")<<'\n';
    return 0;
}
