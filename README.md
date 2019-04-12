# Aggregate-Gamma-Signature

# Signer
  - sign 함수에 private key pem, message를 넣어주면 Merger에서 verify를 할 때 필요한 d, z가 나옴

# Merger
  - aggregate_gamma_signature.h

Shamir Trick을 이용한 aggregate gamma signature

TODO : aggregate, aggregate verify에서 T와 A의 원소가 중복인지 체크하는 부분의 속도가 느려 개선이 필요( hash map을 이용하면 속도 향상이 가능하다고 함 )

- ags.h

Point A쪽 연산이 느린 것 같아 affine coordinate를 대신 사용하면 연산 속도가
빨라진다는 것을 확인

- joint_sparse_form.h

Binary Form 대신 Joint Sparse Form을 사용하면 속도가 더 빨라진다는 논문이 있어 구현해보았으나, 현재 구현한 코드는 Binary Form을 이용한 코드보다 느림

8000개를 처리하는 경우 binary form을 이용한 shamir trick에서는 5개씩 precompute가 가능한데, JSF에서는 2개씩 precompute를 할 수 밖에 없어 4000번 연산해야 함

- test.h

Botan 관련 코드 정리
