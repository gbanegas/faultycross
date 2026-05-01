## Requirements per fault model

### Skip expand 

- This fault changes the commitment with high probability, because all the seeds are used to generate the $B_i$ matrices that are used to create the commitment
- If the node itself, or one of the faulted node's ascendant is published, then this signature will be rejected because the verify algorithm will compute wrong descendant leaves of the faulted node
  - **TODO:** find how to choose the node to have this ?
- In other cases, this will just return a valid signature

### Bit flip and domain sep

- This fault also changes the commitment
- If one of the node's ascendants is published then this signature will be rejected
- In other cases, this will return a valid signature

### Zero seed

- this will always produce a valid but changed signature

### Wrong domain sep

- 