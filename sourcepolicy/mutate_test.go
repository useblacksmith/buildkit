package sourcepolicy

import (
	"context"
	"testing"

	"github.com/moby/buildkit/solver/pb"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/stretchr/testify/require"
)

func TestMutate(t *testing.T) {
	type testCaseOp struct {
		op          *pb.Op
		dest        spb.Destination
		expected    bool
		expectedOp  *pb.Op
		expectedErr string
	}

	testCases := []testCaseOp{
		{
			op: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox:1.34.1-uclibc",
					},
				},
			},
			dest: spb.Destination{
				Identifier: "docker-image://docker.io/library/busybox:1.34.1-uclibc@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
			},
			expected: true,
			expectedOp: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox:1.34.1-uclibc@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
					},
				},
			},
		},
		{
			op: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox",
					},
				},
			},
			dest: spb.Destination{
				Identifier: "docker-image://docker.io/library/busybox:latest@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
			},
			expected: true,
			expectedOp: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox:latest@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
					},
				},
			},
		},
		{
			// Discard the existing digest that might have been resolved by the Dockerfile frontend's MetaResolver.
			op: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			},
			dest: spb.Destination{
				Identifier: "docker-image://docker.io/library/busybox:latest@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
			},
			expected: true,
			expectedOp: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "docker-image://docker.io/library/busybox:latest@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83",
					},
				},
			},
		},
		{
			op: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "https://raw.githubusercontent.com/moby/buildkit/v0.10.1/README.md",
					},
				},
			},
			dest: spb.Destination{
				Identifier: "https://raw.githubusercontent.com/moby/buildkit/v0.10.1/README.md",
				Attrs:      map[string]string{pb.AttrHTTPChecksum: "sha256:6e4b94fc270e708e1068be28bd3551dc6917a4fc5a61293d51bb36e6b75c4b53"},
			},
			expected: true,
			expectedOp: &pb.Op{
				Op: &pb.Op_Source{
					Source: &pb.SourceOp{
						Identifier: "https://raw.githubusercontent.com/moby/buildkit/v0.10.1/README.md",
						Attrs: map[string]string{
							pb.AttrHTTPChecksum: "sha256:6e4b94fc270e708e1068be28bd3551dc6917a4fc5a61293d51bb36e6b75c4b53",
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	for _, tc := range testCases {
		op := *tc.op

		t.Run(op.String(), func(t *testing.T) {
			mutated, err := Mutate(ctx, op.GetSource(), tc.dest.Identifier, tc.dest.Attrs)
			require.Equal(t, tc.expected, mutated)
			if tc.expectedErr != "" {
				require.Error(t, err, tc.expectedErr)
			} else {
				require.Equal(t, tc.expectedOp, &op)
			}
		})
	}
}
