// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build kubeapiserver,orchestrator

package orchestrator

import (
	"time"

	model "github.com/DataDog/agent-payload/process"
	"github.com/DataDog/datadog-agent/pkg/process/config"
	"github.com/DataDog/datadog-agent/pkg/process/util/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	jsoniter "github.com/json-iterator/go"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func processDeploymentList(deploymentList []*v1.Deployment, groupID int32, cfg *config.AgentConfig, clusterName string, clusterID string, withScrubbing bool) ([]model.MessageBody, error) {
	start := time.Now()
	deployMsgs := make([]*model.Deployment, 0, len(deploymentList))

	for d := 0; d < len(deploymentList); d++ {
		depl := deploymentList[d]
		if skip := skipKubernetesResource(depl.UID, depl.ResourceVersion); skip {
			log.Debugf("cache hit. Deployment: did not change: %s", depl.UID)
			continue
		}

		// extract deployment info
		deployModel := extractDeployment(depl)
		// scrub & generate YAML
		if withScrubbing {
			for c := 0; c < len(depl.Spec.Template.Spec.InitContainers); c++ {
				orchestrator.ScrubContainer(&depl.Spec.Template.Spec.InitContainers[c], cfg)
			}
			for c := 0; c < len(deploymentList[d].Spec.Template.Spec.Containers); c++ {
				orchestrator.ScrubContainer(&depl.Spec.Template.Spec.Containers[c], cfg)
			}
		}
		// k8s objects only have json "omitempty" annotations
		// and marshalling is more performant than YAML
		jsonDeploy, err := jsoniter.Marshal(depl)
		if err != nil {
			log.Debugf("Could not marshal deployment to JSON: %s", err)
			continue
		}
		deployModel.Yaml = jsonDeploy

		deployMsgs = append(deployMsgs, deployModel)
	}

	groupSize := len(deployMsgs) / cfg.MaxPerMessage
	if len(deployMsgs)%cfg.MaxPerMessage != 0 {
		groupSize++
	}
	chunked := chunkDeployments(deployMsgs, groupSize, cfg.MaxPerMessage)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorDeployment{
			ClusterName: clusterName,
			Deployments: chunked[i],
			GroupId:     groupID,
			GroupSize:   int32(groupSize),
			ClusterId:   clusterID,
		})
	}

	log.Debugf("Collected & enriched %d deployments in %s", len(deployMsgs), time.Now().Sub(start))
	return messages, nil
}

// skipKubernetesResource checks with a global kubernetes cache whether the resource was already reported.
func skipKubernetesResource(uid types.UID, resourceVersion string) bool {
	value, hit := cache.KubeCache.Get(string(uid))
	if !hit {
		cache.KubeCache.Set(string(uid), resourceVersion, 0)
		return false
	} else if value != resourceVersion {
		cache.KubeCache.Set(string(uid), resourceVersion, 0)
		return false
	} else {
		return true
	}
}

// chunkDeployments formats and chunks the deployments into a slice of chunks using a specific number of chunks.
func chunkDeployments(deploys []*model.Deployment, chunkCount, chunkSize int) [][]*model.Deployment {
	chunks := make([][]*model.Deployment, 0, chunkCount)

	for c := 1; c <= chunkCount; c++ {
		var (
			chunkStart = chunkSize * (c - 1)
			chunkEnd   = chunkSize * (c)
		)
		// last chunk may be smaller than the chunk size
		if c == chunkCount {
			chunkEnd = len(deploys)
		}
		chunks = append(chunks, deploys[chunkStart:chunkEnd])
	}

	return chunks
}

// TODO: look into adding a replicaCache
func processReplicaSetList(rsList []*v1.ReplicaSet, groupID int32, cfg *config.AgentConfig, clusterName string, clusterID string, withScrubbing bool) ([]model.MessageBody, error) {
	start := time.Now()
	rsMsgs := make([]*model.ReplicaSet, 0, len(rsList))

	for rs := 0; rs < len(rsList); rs++ {
		rs := rsList[rs]
		if skip := skipKubernetesResource(rs.UID, rs.ResourceVersion); skip {
			log.Debugf("cache hit. repicaSet: did not change: %s", rs.UID)
			continue
		}

		// extract replica set info
		rsModel := extractReplicaSet(rs)

		// scrub & generate YAML
		if withScrubbing {
			for c := 0; c < len(rs.Spec.Template.Spec.InitContainers); c++ {
				orchestrator.ScrubContainer(&rs.Spec.Template.Spec.InitContainers[c], cfg)
			}
			for c := 0; c < len(rs.Spec.Template.Spec.Containers); c++ {
				orchestrator.ScrubContainer(&rs.Spec.Template.Spec.Containers[c], cfg)
			}
		}

		// k8s objects only have json "omitempty" annotations
		// and marshalling is more performant than YAML
		jsonRS, err := jsoniter.Marshal(rs)
		if err != nil {
			log.Debugf("Could not marshal replica set to JSON: %s", err)
			continue
		}
		rsModel.Yaml = jsonRS

		rsMsgs = append(rsMsgs, rsModel)
	}

	groupSize := len(rsMsgs) / cfg.MaxPerMessage
	if len(rsMsgs)%cfg.MaxPerMessage != 0 {
		groupSize++
	}
	chunked := chunkReplicaSets(rsMsgs, groupSize, cfg.MaxPerMessage)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorReplicaSet{
			ClusterName: clusterName,
			ReplicaSets: chunked[i],
			GroupId:     groupID,
			GroupSize:   int32(groupSize),
			ClusterId:   clusterID,
		})
	}

	log.Debugf("Collected & enriched %d replica sets in %s", len(rsMsgs), time.Now().Sub(start))
	return messages, nil
}

// chunkReplicaSets formats and chunks the replica sets into a slice of chunks using a specific number of chunks.
func chunkReplicaSets(replicaSets []*model.ReplicaSet, chunkCount, chunkSize int) [][]*model.ReplicaSet {
	chunks := make([][]*model.ReplicaSet, 0, chunkCount)

	for c := 1; c <= chunkCount; c++ {
		var (
			chunkStart = chunkSize * (c - 1)
			chunkEnd   = chunkSize * (c)
		)
		// last chunk may be smaller than the chunk size
		if c == chunkCount {
			chunkEnd = len(replicaSets)
		}
		chunks = append(chunks, replicaSets[chunkStart:chunkEnd])
	}

	return chunks
}

// processServiceList process a service list into process messages.
func processServiceList(serviceList []*corev1.Service, groupID int32, cfg *config.AgentConfig, clusterName string, clusterID string) ([]model.MessageBody, error) {
	start := time.Now()
	serviceMsgs := make([]*model.Service, 0, len(serviceList))

	for s := 0; s < len(serviceList); s++ {
		svc := serviceList[s]
		if skip := skipKubernetesResource(svc.UID, svc.ResourceVersion); skip {
			log.Debugf("cache hit. service: did not change: %s", svc.UID)
			continue
		}

		serviceModel := extractService(svc)

		// k8s objects only have json "omitempty" annotations
		// + marshalling is more performant than YAML
		jsonSvc, err := jsoniter.Marshal(svc)
		if err != nil {
			log.Debugf("Could not marshal service to JSON: %s", err)
			continue
		}
		serviceModel.Yaml = jsonSvc

		serviceMsgs = append(serviceMsgs, serviceModel)
	}

	groupSize := len(serviceMsgs) / cfg.MaxPerMessage
	if len(serviceMsgs)%cfg.MaxPerMessage > 0 {
		groupSize++
	}

	chunks := chunkServices(serviceMsgs, groupSize, cfg.MaxPerMessage)
	messages := make([]model.MessageBody, 0, groupSize)

	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorService{
			ClusterName: clusterName,
			ClusterId:   clusterID,
			GroupId:     groupID,
			GroupSize:   int32(groupSize),
			Services:    chunks[i],
		})
	}

	log.Debugf("Collected & enriched %d services in %s", len(serviceMsgs), time.Now().Sub(start))
	return messages, nil
}

// chunkServices chunks the given list of services, honoring the given chunk count and size.
// The last chunk may be smaller than the others.
func chunkServices(services []*model.Service, chunkCount, chunkSize int) [][]*model.Service {
	chunks := make([][]*model.Service, 0, chunkCount)

	for c := 1; c <= chunkCount; c++ {
		var (
			chunkStart = chunkSize * (c - 1)
			chunkEnd   = chunkSize * (c)
		)
		// last chunk may be smaller than the chunk size
		if c == chunkCount {
			chunkEnd = len(services)
		}
		chunks = append(chunks, services[chunkStart:chunkEnd])
	}

	return chunks
}
